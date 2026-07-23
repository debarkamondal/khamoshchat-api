use crate::{error::AppError, state::AppState};
use aws_sdk_dynamodb::types::{AttributeValue, Put, TransactWriteItem};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub async fn get_item(
    state: &AppState,
    pk: &str,
    sk: &str,
) -> Result<Option<HashMap<String, AttributeValue>>, AppError> {
    let res = state
        .dynamo
        .get_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S(sk.to_string()))
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                "DynamoDB get_item error: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal("Database error".into())
        })?;

    Ok(res.item)
}

pub async fn query_gsi_lookup(
    state: &AppState,
    lookup_value: &str,
) -> Result<Option<HashMap<String, AttributeValue>>, AppError> {
    let res = state
        .dynamo
        .query()
        .table_name(&state.primary_table)
        .index_name(&state.gsi_lookup_index)
        .key_condition_expression("#lookup = :val")
        .expression_attribute_names("#lookup", "lookup")
        .expression_attribute_values(":val", AttributeValue::S(lookup_value.to_string()))
        .limit(1)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                "DynamoDB query GSI error: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal("Database error".into())
        })?;

    Ok(res.items.unwrap_or_default().into_iter().next())
}

pub async fn transact_write_items(
    state: &AppState,
    items: Vec<HashMap<String, AttributeValue>>,
) -> Result<(), AppError> {
    let mut transact_items = Vec::new();

    for item in items {
        let put = Put::builder()
            .table_name(&state.primary_table)
            .set_item(Some(item))
            .build()
            .unwrap();

        transact_items.push(TransactWriteItem::builder().put(put).build());
    }

    state
        .dynamo
        .transact_write_items()
        .set_transact_items(Some(transact_items))
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                "DynamoDB transact_write_items error: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal(format!(
                "Database error: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            ))
        })?;

    Ok(())
}

pub async fn update_item_fcm(
    state: &AppState,
    pk: &str,
    sk: &str,
    fcm_token: &str,
) -> Result<(), AppError> {
    // Primary update: write to the DEVICE# item (authoritative source for notifications).
    // The condition ensures the device exists before updating.
    state
        .dynamo
        .update_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S(sk.to_string()))
        .update_expression("SET fcmToken = :token")
        .expression_attribute_values(":token", AttributeValue::S(fcm_token.to_string()))
        .condition_expression("attribute_exists(signedDeviceKey)")
        .send()
        .await
        .map_err(|e| {
            if let aws_sdk_dynamodb::error::SdkError::ServiceError(ref se) = e {
                if se.err().is_conditional_check_failed_exception() {
                    return AppError::NotFound("Device not found or not registered".to_string());
                }
            }
            tracing::error!(
                "Failed to update fcmToken in DynamoDB: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal("Database error".into())
        })?;

    // Secondary update: sync the denormalized fcmToken on the PROFILE item.
    // This is best-effort — a failure is logged but does not fail the request,
    // since the DEVICE# item is the authoritative source for push delivery.
    let profile_result = state
        .dynamo
        .update_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S("PROFILE".to_string()))
        .update_expression("SET fcmToken = :token")
        .expression_attribute_values(":token", AttributeValue::S(fcm_token.to_string()))
        .send()
        .await;

    if let Err(ref e) = profile_result {
        tracing::warn!(
            "Failed to sync fcmToken to PROFILE item (non-fatal): {}",
            aws_sdk_dynamodb::error::DisplayErrorContext(e)
        );
    }

    Ok(())
}


pub async fn pop_opk(
    state: &AppState,
    pk: &str,
    sk: &str,
    opk_index: usize,
    expected_opk: &str,
) -> Result<(), AppError> {
    state
        .dynamo
        .update_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S(sk.to_string()))
        .update_expression(format!("REMOVE opks[{}]", opk_index))
        .condition_expression(format!("opks[{}] = :expected", opk_index))
        .expression_attribute_values(":expected", AttributeValue::S(expected_opk.to_string()))
        .send()
        .await
        .map_err(|e| {
            if let aws_sdk_dynamodb::error::SdkError::ServiceError(ref se) = e {
                if se.err().is_conditional_check_failed_exception() {
                    return AppError::Conflict("OPK conflict detected".to_string());
                }
            }
            tracing::error!(
                "Failed to pop OPK in DynamoDB: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal("Database error".into())
        })?;

    Ok(())
}

/// Persist an offline message record for the recipient in DynamoDB.
///
/// Schema:
/// - pk: `USER#<recipient_id>`
/// - sk: `OFFLINE_MSG#<timestamp_ms>#<uuid>` (time-sortable, unique per message)
/// - ttl: Unix epoch 30 days from now — DynamoDB auto-expires old records.
pub async fn put_offline_message(
    state: &AppState,
    recipient_id: &str,
    sender_id: &str,
    sender_device_id: &str,
    topic: &str,
    payload: &str,
) -> Result<(), AppError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let ttl_secs = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs())
        + (30 * 24 * 60 * 60); // 30 days

    let pk = format!("USER#{}", recipient_id);
    let sk = format!("OFFLINE_MSG#{}#{}", now_ms, Uuid::new_v4());

    let mut item = HashMap::new();
    item.insert("pk".to_string(), AttributeValue::S(pk));
    item.insert("sk".to_string(), AttributeValue::S(sk));
    item.insert("senderId".to_string(), AttributeValue::S(sender_id.to_string()));
    item.insert("senderDeviceId".to_string(), AttributeValue::S(sender_device_id.to_string()));
    item.insert("topic".to_string(), AttributeValue::S(topic.to_string()));
    item.insert("payload".to_string(), AttributeValue::S(payload.to_string()));
    item.insert("createdAt".to_string(), AttributeValue::N(now_ms.to_string()));
    item.insert("ttl".to_string(), AttributeValue::N(ttl_secs.to_string()));

    state
        .dynamo
        .put_item()
        .table_name(&state.primary_table)
        .set_item(Some(item))
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to persist offline message: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal("Failed to store offline message".into())
        })?;

    Ok(())
}

/// Remove the FCM token from both the `DEVICE#` and `PROFILE` items.
/// Called when FCM returns UNREGISTERED, indicating the app was uninstalled
/// or the token has been rotated.
pub async fn clear_device_fcm_token(
    state: &AppState,
    pk: &str,
    device_sk: &str,
) -> Result<(), AppError> {
    // Remove from DEVICE# item (primary)
    let device_result = state
        .dynamo
        .update_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S(device_sk.to_string()))
        .update_expression("REMOVE fcmToken")
        .send()
        .await;

    if let Err(ref e) = device_result {
        tracing::warn!(
            "Failed to clear fcmToken from DEVICE item (non-fatal): {}",
            aws_sdk_dynamodb::error::DisplayErrorContext(e)
        );
    }

    // Remove from PROFILE item (denormalized copy, best-effort)
    let profile_result = state
        .dynamo
        .update_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S("PROFILE".to_string()))
        .update_expression("REMOVE fcmToken")
        .send()
        .await;

    if let Err(ref e) = profile_result {
        tracing::warn!(
            "Failed to clear fcmToken from PROFILE item (non-fatal): {}",
            aws_sdk_dynamodb::error::DisplayErrorContext(e)
        );
    }

    Ok(())
}
