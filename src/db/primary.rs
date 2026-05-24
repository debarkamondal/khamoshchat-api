use aws_sdk_dynamodb::types::{AttributeValue, Put, TransactWriteItem};
use std::collections::HashMap;
use crate::{state::AppState, error::AppError};

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
            tracing::error!("DynamoDB get_item error: {}", aws_sdk_dynamodb::error::DisplayErrorContext(&e));
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
            tracing::error!("DynamoDB query GSI error: {}", aws_sdk_dynamodb::error::DisplayErrorContext(&e));
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
            
        transact_items.push(
            TransactWriteItem::builder()
                .put(put)
                .build()
        );
    }

    state
        .dynamo
        .transact_write_items()
        .set_transact_items(Some(transact_items))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("DynamoDB transact_write_items error: {}", aws_sdk_dynamodb::error::DisplayErrorContext(&e));
            AppError::Internal(format!("Database error: {}", aws_sdk_dynamodb::error::DisplayErrorContext(&e)))
        })?;

    Ok(())
}

pub async fn update_item_fcm(
    state: &AppState,
    pk: &str,
    sk: &str,
    fcm_token: &str,
) -> Result<(), AppError> {
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
            tracing::error!("Failed to update fcmToken in DynamoDB: {}", aws_sdk_dynamodb::error::DisplayErrorContext(&e));
            AppError::Internal("Database error".into())
        })?;

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
            tracing::error!("Failed to pop OPK in DynamoDB: {}", aws_sdk_dynamodb::error::DisplayErrorContext(&e));
            AppError::Internal("Database error".into())
        })?;

    Ok(())
}

pub async fn get_user_device(
    state: &AppState,
    pk: &str,
) -> Result<Option<String>, AppError> {
    let res = state
        .dynamo
        .query()
        .table_name(&state.primary_table)
        .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
        .expression_attribute_values(":pk", AttributeValue::S(pk.to_string()))
        .expression_attribute_values(":prefix", AttributeValue::S("DEVICE#".to_string()))
        .limit(1)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("DynamoDB query device error: {}", aws_sdk_dynamodb::error::DisplayErrorContext(&e));
            AppError::Internal("Database error".into())
        })?;

    if let Some(item) = res.items.unwrap_or_default().into_iter().next() {
        if let Some(sk_val) = item.get("sk").and_then(|v| v.as_s().ok()) {
            if let Some(device_id) = sk_val.strip_prefix("DEVICE#") {
                return Ok(Some(device_id.to_string()));
            }
        }
    }
    Ok(None)
}

