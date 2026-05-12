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
            tracing::error!("DynamoDB get_item error: {}", e);
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
            tracing::error!("DynamoDB query GSI error: {}", e);
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
            tracing::error!("DynamoDB transact_write_items error: {:?}", e);
            AppError::Internal(format!("Database error: {}", e))
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
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to update fcmToken in DynamoDB: {}", e);
            AppError::Internal("Database error".into())
        })?;

    Ok(())
}

pub async fn pop_opk(
    state: &AppState,
    pk: &str,
    sk: &str,
    opk_index: usize,
) -> Result<(), AppError> {
    state
        .dynamo
        .update_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S(sk.to_string()))
        .update_expression(format!("REMOVE opks[{}]", opk_index))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to pop OPK in DynamoDB: {}", e);
            AppError::Internal("Database error".into())
        })?;

    Ok(())
}
