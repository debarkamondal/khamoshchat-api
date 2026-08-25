use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, TransactWriteItem};
use axum::{extract::State, Json};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{
    crypto::verify_signed_signature,
    db::{
        keys::{
            device_sk, email_lookup_pk, lookup_sk, pending_reg_key, phone_lookup_pk, profile_sk,
            user_pk,
        },
        primary::transact_write_items,
        temp::{delete_temp_key, get_temp_json},
    },
    error::AppError,
    models::temp_registration::TempRegistration,
    state::AppState,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    pub user_id: String,
    pub phone: String,
    pub i_key: String,
    pub signed_pre_key: String,
    pub pre_key_sign: String,
    pub pre_key_vrf: String,
    #[serde(default)]
    pub opks: Vec<String>,
    pub signed_device_key: String,
    pub dev_key_sign: String,
    pub dev_key_vrf: String,
    pub fcm_token: Option<String>,
}

pub async fn register_device(
    State(state): State<AppState>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if req.phone.trim().is_empty() {
        return Err(AppError::BadRequest("Phone number is required".to_string()));
    }

    let parsed_uuid = uuid::Uuid::parse_str(&req.user_id)
        .map_err(|_| AppError::BadRequest("Invalid userId format: must be UUID".to_string()))?;
    if parsed_uuid.get_version_num() != 4 {
        return Err(AppError::BadRequest(
            "Invalid userId format: must be UUID v4".to_string(),
        ));
    }

    // 1. Fetch pending record from Redis
    let redis_key = pending_reg_key(&req.user_id);
    let pending_json = get_temp_json(&state, &redis_key).await?;

    let pending_json = pending_json.ok_or_else(|| {
        AppError::NotFound("Pending registration not found or expired".to_string())
    })?;

    let pending_data: TempRegistration = serde_json::from_str(&pending_json).map_err(|e| {
        tracing::error!("Corrupt pending registration data: {}", e);
        AppError::Internal("Internal server error".to_string())
    })?;

    // 2. Verify crypto
    verify_signed_signature(
        &req.i_key,
        &req.signed_pre_key,
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

    // 3. Check for existing profile to preserve device_id / createdAt if re-registering
    let pk = user_pk(&req.user_id);
    let existing_profile_opt = crate::db::primary::get_item(&state, &pk, profile_sk()).await?;

    let (device_id, created_at, existing_picture, old_phone) =
        if let Some(ref existing) = existing_profile_opt {
            let dev_id = existing
                .get("deviceId")
                .and_then(|v| v.as_s().ok())
                .cloned()
                .unwrap_or_else(|| Uuid::new_v4().to_string());

            let created = existing
                .get("createdAt")
                .and_then(|v| v.as_n().ok())
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(pending_data.created_at);

            let pic = existing.get("picture").and_then(|v| v.as_s().ok()).cloned();

            let old_ph = existing.get("phone").and_then(|v| v.as_s().ok()).cloned();

            (dev_id, created, pic, old_ph)
        } else {
            (
                Uuid::new_v4().to_string(),
                pending_data.created_at,
                None,
                None,
            )
        };

    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Profile Item (zero-GSI, no lookup attribute)
    let mut profile_item = HashMap::new();
    profile_item.insert("pk".to_string(), AttributeValue::S(pk.clone()));
    profile_item.insert(
        "sk".to_string(),
        AttributeValue::S(profile_sk().to_string()),
    );
    profile_item.insert("name".to_string(), AttributeValue::S(pending_data.name));
    profile_item.insert(
        "email".to_string(),
        AttributeValue::S(pending_data.email.clone()),
    );
    profile_item.insert("phone".to_string(), AttributeValue::S(req.phone.clone()));
    if let Some(pic) = pending_data.picture.or(existing_picture) {
        profile_item.insert("picture".to_string(), AttributeValue::S(pic));
    }

    profile_item.insert("iKey".to_string(), AttributeValue::S(req.i_key));
    profile_item.insert(
        "signedPreKey".to_string(),
        AttributeValue::S(req.signed_pre_key),
    );
    profile_item.insert("signature".to_string(), AttributeValue::S(req.pre_key_sign));

    if !req.opks.is_empty() {
        let opks_attr: Vec<AttributeValue> = req.opks.into_iter().map(AttributeValue::S).collect();
        profile_item.insert("opks".to_string(), AttributeValue::L(opks_attr));
    }
    profile_item.insert(
        "createdAt".to_string(),
        AttributeValue::N(created_at.to_string()),
    );
    profile_item.insert(
        "updatedAt".to_string(),
        AttributeValue::N(now_millis.to_string()),
    );
    // Device fields merged into profile (until multi-device is implemented)
    profile_item.insert("deviceId".to_string(), AttributeValue::S(device_id.clone()));
    profile_item.insert(
        "signedDeviceKey".to_string(),
        AttributeValue::S(req.signed_device_key.clone()),
    );
    if let Some(ref fcm) = req.fcm_token {
        profile_item.insert("fcmToken".to_string(), AttributeValue::S(fcm.clone()));
    }

    // Device Item
    let mut device_item = HashMap::new();
    device_item.insert("pk".to_string(), AttributeValue::S(pk.clone()));
    device_item.insert("sk".to_string(), AttributeValue::S(device_sk(&device_id)));
    device_item.insert(
        "signedDeviceKey".to_string(),
        AttributeValue::S(req.signed_device_key),
    );
    if let Some(fcm) = req.fcm_token {
        device_item.insert("fcmToken".to_string(), AttributeValue::S(fcm));
    }
    device_item.insert(
        "createdAt".to_string(),
        AttributeValue::N(created_at.to_string()),
    );
    device_item.insert(
        "updatedAt".to_string(),
        AttributeValue::N(now_millis.to_string()),
    );

    let mut transact_items = Vec::new();

    // 1. Put Profile
    let put_profile = Put::builder()
        .table_name(&state.primary_table)
        .set_item(Some(profile_item))
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build profile put: {}", e);
            AppError::Internal("Database error".to_string())
        })?;
    transact_items.push(TransactWriteItem::builder().put(put_profile).build());

    // 2. Put Device
    let put_device = Put::builder()
        .table_name(&state.primary_table)
        .set_item(Some(device_item))
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build device put: {}", e);
            AppError::Internal("Database error".to_string())
        })?;
    transact_items.push(TransactWriteItem::builder().put(put_device).build());

    if existing_profile_opt.is_none() {
        // New user: write both EMAIL# and PHONE# pointer items with uniqueness conditions
        let mut email_pointer = HashMap::new();
        email_pointer.insert(
            "pk".to_string(),
            AttributeValue::S(email_lookup_pk(&pending_data.email)),
        );
        email_pointer.insert("sk".to_string(), AttributeValue::S(lookup_sk().to_string()));
        email_pointer.insert("userId".to_string(), AttributeValue::S(req.user_id.clone()));

        let put_email_ptr = Put::builder()
            .table_name(&state.primary_table)
            .set_item(Some(email_pointer))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|e| {
                tracing::error!("Failed to build email pointer put: {}", e);
                AppError::Internal("Database error".to_string())
            })?;
        transact_items.push(TransactWriteItem::builder().put(put_email_ptr).build());

        let mut phone_pointer = HashMap::new();
        phone_pointer.insert(
            "pk".to_string(),
            AttributeValue::S(phone_lookup_pk(&req.phone)),
        );
        phone_pointer.insert("sk".to_string(), AttributeValue::S(lookup_sk().to_string()));
        phone_pointer.insert("userId".to_string(), AttributeValue::S(req.user_id.clone()));

        let put_phone_ptr = Put::builder()
            .table_name(&state.primary_table)
            .set_item(Some(phone_pointer))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|e| {
                tracing::error!("Failed to build phone pointer put: {}", e);
                AppError::Internal("Database error".to_string())
            })?;
        transact_items.push(TransactWriteItem::builder().put(put_phone_ptr).build());
    } else {
        // Re-registering user:
        // Email pointer is immutable (never modified/deleted).
        // Only update phone pointer if phone number changed.
        let phone_changed = match old_phone {
            Some(ref old) => old.trim() != req.phone.trim(),
            None => true,
        };

        if phone_changed {
            if let Some(ref old) = old_phone {
                if !old.trim().is_empty() {
                    let delete_old_phone_ptr = Delete::builder()
                        .table_name(&state.primary_table)
                        .key("pk", AttributeValue::S(phone_lookup_pk(old)))
                        .key("sk", AttributeValue::S(lookup_sk().to_string()))
                        .build()
                        .map_err(|e| {
                            tracing::error!("Failed to build delete phone pointer: {}", e);
                            AppError::Internal("Database error".to_string())
                        })?;
                    transact_items.push(
                        TransactWriteItem::builder()
                            .delete(delete_old_phone_ptr)
                            .build(),
                    );
                }
            }

            let mut new_phone_pointer = HashMap::new();
            new_phone_pointer.insert(
                "pk".to_string(),
                AttributeValue::S(phone_lookup_pk(&req.phone)),
            );
            new_phone_pointer.insert("sk".to_string(), AttributeValue::S(lookup_sk().to_string()));
            new_phone_pointer.insert("userId".to_string(), AttributeValue::S(req.user_id.clone()));

            let put_new_phone_ptr = Put::builder()
                .table_name(&state.primary_table)
                .set_item(Some(new_phone_pointer))
                .condition_expression("attribute_not_exists(pk)")
                .build()
                .map_err(|e| {
                    tracing::error!("Failed to build new phone pointer put: {}", e);
                    AppError::Internal("Database error".to_string())
                })?;
            transact_items.push(TransactWriteItem::builder().put(put_new_phone_ptr).build());
        }
    }

    // Transact write
    transact_write_items(&state, transact_items).await?;

    // 4. Delete Redis key
    let _ = delete_temp_key(&state, &redis_key).await;

    tracing::info!(user_id = %req.user_id, device_id = %device_id, "Device registered successfully");

    // 5. Response
    Ok(Json(serde_json::json!({
        "status": "success",
        "userId": req.user_id,
        "deviceId": device_id,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFcmTokenRequest {
    pub device_id: String,
    pub fcm_token: String,
}

pub async fn update_fcm_token(
    State(state): State<AppState>,
    auth_user: crate::auth::signature::AuthenticatedUser,
    Json(req): Json<UpdateFcmTokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    uuid::Uuid::parse_str(&req.device_id)
        .map_err(|_| AppError::BadRequest("Invalid deviceId format: must be UUID".to_string()))?;

    let pk = user_pk(&auth_user.user_id);
    let sk = device_sk(&req.device_id);

    // Update FCM token in DynamoDB
    crate::db::primary::update_item_fcm(&state, &pk, &sk, &req.fcm_token).await?;

    tracing::info!(user_id = %auth_user.user_id, device_id = %req.device_id, "FCM token updated successfully");

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "FCM token updated",
    })))
}
