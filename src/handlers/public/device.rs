use aws_sdk_dynamodb::types::AttributeValue;
use axum::{extract::State, Json};
use serde::Deserialize;
use std::collections::HashMap;

use crate::{
    crypto::verify_signed_signature,
    db::{
        keys::{device_sk, pending_reg_key, profile_sk, user_pk},
        primary::transact_write_items,
        temp::{delete_temp_key, get_temp_json},
    },
    error::AppError,
    models::temp_registration::TempRegistration,
    state::AppState,
};

#[derive(Deserialize)]
pub struct RegisterDeviceRequest {
    pub user_id: String,
    pub phone: String,
    #[serde(rename = "iKey")]
    pub i_key: String,
    #[serde(rename = "signedPreKey")]
    pub signed_prekey: String,
    #[serde(rename = "preKeySign")]
    pub pre_key_sign: String,
    #[serde(rename = "preKeyVrf")]
    pub pre_key_vrf: String,
    #[serde(default)]
    pub opks: Vec<String>,
    pub device_id: String,
    #[serde(rename = "signDevKey")]
    pub signed_device_key: String,
    #[serde(rename = "devKeySign")]
    pub dev_key_sign: String,
    #[serde(rename = "devKeyVrf")]
    pub dev_key_vrf: String,
    #[serde(rename = "fcmToken")]
    pub fcm_token: Option<String>,
}

pub async fn register_device(
    State(state): State<AppState>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // 1. Fetch pending record from Redis
    let redis_key = pending_reg_key(&req.user_id);
    let pending_json = get_temp_json(&state, &redis_key).await?;

    let pending_json = pending_json.ok_or_else(|| {
        AppError::NotFound("Pending registration not found or expired".to_string())
    })?;

    let pending_data: TempRegistration = serde_json::from_str(&pending_json)
        .map_err(|e| AppError::Internal(format!("Corrupt pending registration data: {}", e)))?;

    // 2. Verify crypto
    verify_signed_signature(
        &req.i_key,
        &req.signed_prekey,
        &req.pre_key_sign,
        &req.pre_key_vrf,
        "signedPreKey",
    )?;
    verify_signed_signature(
        &req.i_key,
        &req.signed_device_key,
        &req.dev_key_sign,
        &req.dev_key_vrf,
        "signedDeviceKey",
    )?;

    // 3. Write to Primary Table (transact)
    let pk = user_pk(&req.user_id);
    let now_millis = pending_data.created_at;

    // Profile Item
    let mut profile_item = HashMap::new();
    profile_item.insert("pk".to_string(), AttributeValue::S(pk.clone()));
    profile_item.insert("sk".to_string(), AttributeValue::S(profile_sk()));
    profile_item.insert("lookup".to_string(), AttributeValue::S(req.phone.clone()));

    profile_item.insert("name".to_string(), AttributeValue::S(pending_data.name));
    profile_item.insert("email".to_string(), AttributeValue::S(pending_data.email));
    profile_item.insert("phone".to_string(), AttributeValue::S(req.phone));
    if let Some(pic) = pending_data.picture {
        profile_item.insert("picture".to_string(), AttributeValue::S(pic));
    }

    profile_item.insert("iKey".to_string(), AttributeValue::S(req.i_key));
    profile_item.insert(
        "signedPreKey".to_string(),
        AttributeValue::S(req.signed_prekey),
    );
    profile_item.insert("signature".to_string(), AttributeValue::S(req.pre_key_sign));

    if !req.opks.is_empty() {
        let opks_attr: Vec<AttributeValue> = req
            .opks
            .into_iter()
            .map(|opk| AttributeValue::S(opk))
            .collect();
        profile_item.insert("opks".to_string(), AttributeValue::L(opks_attr));
    }
    profile_item.insert(
        "createdAt".to_string(),
        AttributeValue::N(now_millis.to_string()),
    );

    // Device Item
    let mut device_item = HashMap::new();
    device_item.insert("pk".to_string(), AttributeValue::S(pk.clone()));
    device_item.insert(
        "sk".to_string(),
        AttributeValue::S(device_sk(&req.device_id)),
    );
    device_item.insert(
        "signedDeviceKey".to_string(),
        AttributeValue::S(req.signed_device_key),
    );
    if let Some(fcm) = req.fcm_token {
        device_item.insert("fcmToken".to_string(), AttributeValue::S(fcm));
    }
    device_item.insert(
        "createdAt".to_string(),
        AttributeValue::N(now_millis.to_string()),
    );

    // Transact write
    transact_write_items(&state, vec![profile_item, device_item]).await?;

    // 4. Delete Redis key
    let _ = delete_temp_key(&state, &redis_key).await;

    // 5. Response
    Ok(Json(serde_json::json!({
        "status": "success",
        "userId": req.user_id,
        "deviceId": req.device_id,
    })))
}

#[derive(Deserialize)]
pub struct UpdateFcmTokenRequest {
    pub device_id: String,
    #[serde(rename = "fcmToken")]
    pub fcm_token: String,
}

pub async fn update_fcm_token(
    State(state): State<AppState>,
    auth_user: crate::auth::signature::AuthenticatedUser,
    Json(req): Json<UpdateFcmTokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pk = user_pk(&auth_user.user_id);
    let sk = device_sk(&req.device_id);

    // Update FCM token in DynamoDB
    crate::db::primary::update_item_fcm(&state, &pk, &sk, &req.fcm_token).await?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "FCM token updated",
    })))
}
