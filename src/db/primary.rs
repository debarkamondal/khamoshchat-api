use crate::{
    db::keys::{email_lookup_pk, lookup_sk, phone_lookup_pk, user_pk},
    error::AppError,
    state::AppState,
};
use aws_sdk_dynamodb::types::{AttributeValue, DeleteRequest, TransactWriteItem, WriteRequest};
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

pub async fn resolve_user_by_identifier(
    state: &AppState,
    identifier: &str,
) -> Result<Option<HashMap<String, AttributeValue>>, AppError> {
    let (pk, sk) = if identifier.contains('@') {
        (
            crate::db::keys::email_lookup_pk(identifier),
            crate::db::keys::lookup_sk(),
        )
    } else {
        (
            crate::db::keys::phone_lookup_pk(identifier),
            crate::db::keys::lookup_sk(),
        )
    };

    let pointer = get_item(state, &pk, sk).await?;
    let pointer_item = match pointer {
        Some(item) => item,
        None => return Ok(None),
    };

    let user_id = match pointer_item.get("userId").and_then(|v| v.as_s().ok()) {
        Some(uid) => uid,
        None => return Ok(None),
    };

    let user_pk = crate::db::keys::user_pk(user_id);
    let profile_sk = crate::db::keys::profile_sk();
    get_item(state, &user_pk, profile_sk).await
}

pub async fn transact_write_items(
    state: &AppState,
    items: Vec<TransactWriteItem>,
) -> Result<(), AppError> {
    state
        .dynamo
        .transact_write_items()
        .set_transact_items(Some(items))
        .send()
        .await
        .map_err(|e| {
            if let aws_sdk_dynamodb::error::SdkError::ServiceError(ref se) = e {
                if se.err().is_transaction_canceled_exception() {
                    return AppError::Conflict(
                        "Conflict: An item condition check failed or already exists".to_string(),
                    );
                }
            }
            tracing::error!(
                "DynamoDB transact_write_items error: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal("Database error".into())
        })?;

    Ok(())
}

pub async fn update_item_fcm(
    state: &AppState,
    pk: &str,
    sk: &str,
    fcm_token: &str,
) -> Result<(), AppError> {
    // Secondary update: sync the denormalized fcmToken on the PROFILE item.
    // This is best-effort — a failure is logged but does not fail the request,
    // since the DEVICE# item is the authoritative source for push delivery.
    let profile_future = state
        .dynamo
        .update_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S("PROFILE".to_string()))
        .update_expression("SET fcmToken = :token")
        .expression_attribute_values(":token", AttributeValue::S(fcm_token.to_string()))
        .send();

    // Primary update: write to the DEVICE# item (authoritative source for notifications).
    // The condition ensures the device exists before updating.
    let device_future = state
        .dynamo
        .update_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S(sk.to_string()))
        .update_expression("SET fcmToken = :token")
        .expression_attribute_values(":token", AttributeValue::S(fcm_token.to_string()))
        .condition_expression("attribute_exists(signedDeviceKey)")
        .send();

    let (device_result, profile_result) = tokio::join!(device_future, profile_future);

    device_result.map_err(|e| {
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let now_ms = now.as_millis() as u64;
    let ttl_secs = now.as_secs() + (30 * 24 * 60 * 60); // 30 days

    let pk = format!("USER#{}", recipient_id);
    let sk = format!("OFFLINE_MSG#{}#{}", now_ms, Uuid::new_v4());

    let mut item = HashMap::new();
    item.insert("pk".to_string(), AttributeValue::S(pk));
    item.insert("sk".to_string(), AttributeValue::S(sk));
    item.insert(
        "senderId".to_string(),
        AttributeValue::S(sender_id.to_string()),
    );
    item.insert(
        "senderDeviceId".to_string(),
        AttributeValue::S(sender_device_id.to_string()),
    );
    item.insert("topic".to_string(), AttributeValue::S(topic.to_string()));
    item.insert(
        "payload".to_string(),
        AttributeValue::S(payload.to_string()),
    );
    item.insert(
        "createdAt".to_string(),
        AttributeValue::N(now_ms.to_string()),
    );
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

async fn execute_batch_delete(
    state: &AppState,
    requests: Vec<WriteRequest>,
) -> Result<(), AppError> {
    if requests.is_empty() {
        return Ok(());
    }

    state
        .dynamo
        .batch_write_item()
        .request_items(&state.primary_table, requests)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to execute batch_write_item delete: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal("Database error".into())
        })?;

    Ok(())
}

/// Permanently delete a user account and cascade-delete all associated items:
/// - Partition items: PROFILE, DEVICE#*, OFFLINE_MSG#*
/// - Lookup pointers: EMAIL#<email>, PHONE#<phone>
///
/// Collects all keys, chunks them into 25-item DynamoDB batch delete requests,
/// and executes concurrent batch deletions joined via `tokio::join!`.
pub async fn delete_user_account(state: &AppState, user_id: &str) -> Result<(), AppError> {
    let pk = user_pk(user_id);

    // 1. Query all items under USER#<user_id>
    let query_res = state
        .dynamo
        .query()
        .table_name(&state.primary_table)
        .key_condition_expression("pk = :pk")
        .expression_attribute_values(":pk", AttributeValue::S(pk.clone()))
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to query user items for deletion: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal("Database error".into())
        })?;

    let items = query_res.items.unwrap_or_default();
    if items.is_empty() {
        return Err(AppError::NotFound("User not found".to_string()));
    }

    let mut keys_to_delete: Vec<(String, String)> = Vec::new();
    let mut email_to_delete: Option<String> = None;
    let mut phone_to_delete: Option<String> = None;

    for item in items {
        if let Some(sk) = item.get("sk").and_then(|v| v.as_s().ok()) {
            keys_to_delete.push((pk.clone(), sk.clone()));

            if sk == "PROFILE" {
                if let Some(email) = item.get("email").and_then(|v| v.as_s().ok()) {
                    if !email.trim().is_empty() {
                        email_to_delete = Some(email.clone());
                    }
                }
                if let Some(phone) = item.get("phone").and_then(|v| v.as_s().ok()) {
                    if !phone.trim().is_empty() {
                        phone_to_delete = Some(phone.clone());
                    }
                }
            }
        }
    }

    // 2. Add email & phone lookup pointer keys
    if let Some(email) = email_to_delete {
        keys_to_delete.push((email_lookup_pk(&email), lookup_sk().to_string()));
    }
    if let Some(phone) = phone_to_delete {
        keys_to_delete.push((phone_lookup_pk(&phone), lookup_sk().to_string()));
    }

    // 3. Formulate WriteRequest items
    let mut write_requests = Vec::new();
    for (item_pk, item_sk) in keys_to_delete {
        let delete_req = DeleteRequest::builder()
            .key("pk", AttributeValue::S(item_pk))
            .key("sk", AttributeValue::S(item_sk))
            .build()
            .map_err(|e| {
                tracing::error!("Failed to build delete request: {}", e);
                AppError::Internal("Database error".to_string())
            })?;

        write_requests.push(WriteRequest::builder().delete_request(delete_req).build());
    }

    // 4. Chunk into batches of up to 25 items (DynamoDB BatchWriteItem maximum)
    let chunks: Vec<Vec<WriteRequest>> = write_requests
        .chunks(25)
        .map(|chunk| chunk.to_vec())
        .collect();

    if chunks.is_empty() {
        return Ok(());
    }

    // Split batches into two concurrent worker branches and join them with tokio::join!
    let mid = chunks.len().div_ceil(2);
    let (left_chunks, right_chunks) = chunks.split_at(mid);

    let state_left = state.clone();
    let state_right = state.clone();
    let left_batches = left_chunks.to_vec();
    let right_batches = right_chunks.to_vec();

    let left_future = async move {
        for batch in left_batches {
            execute_batch_delete(&state_left, batch).await?;
        }
        Ok::<(), AppError>(())
    };

    let right_future = async move {
        for batch in right_batches {
            execute_batch_delete(&state_right, batch).await?;
        }
        Ok::<(), AppError>(())
    };

    let (res_left, res_right) = tokio::join!(left_future, right_future);
    res_left?;
    res_right?;

    Ok(())
}

/// Store user abuse report in DynamoDB:
/// - pk: `REPORTER#<reporter_id>`
/// - sk: `<reported_id>`
/// - reason: abuse reason string
/// - messages: serialized audit messages
/// - createdAt: epoch ms
pub async fn put_user_report(
    state: &AppState,
    reporter_id: &str,
    reported_id: &str,
    reason: &str,
    messages_json: &str,
) -> Result<(), AppError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let pk = crate::db::keys::reporter_pk(reporter_id);
    let sk = reported_id;

    let mut item = HashMap::new();
    item.insert("pk".to_string(), AttributeValue::S(pk));
    item.insert("sk".to_string(), AttributeValue::S(sk.to_string()));
    item.insert("reason".to_string(), AttributeValue::S(reason.to_string()));
    item.insert(
        "messages".to_string(),
        AttributeValue::S(messages_json.to_string()),
    );
    item.insert(
        "createdAt".to_string(),
        AttributeValue::N(now_ms.to_string()),
    );

    state
        .dynamo
        .put_item()
        .table_name(&state.primary_table)
        .set_item(Some(item))
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to put user report in DynamoDB: {}",
                aws_sdk_dynamodb::error::DisplayErrorContext(&e)
            );
            AppError::Internal("Database error".into())
        })?;

    Ok(())
}
