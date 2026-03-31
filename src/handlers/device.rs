use aws_sdk_dynamodb::types::AttributeValue;
use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose, Engine as _};
use libsignal_dezire::vxeddsa::vxeddsa_verify;
use serde::Deserialize;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct RegisterFcmTokenRequest {
    pub phone: String,
    #[serde(rename = "fcmToken")]
    pub fcm_token: String,
    pub signature: String,
    pub vrf: String,
}

// ─── POST /register/device/fcm ───

pub async fn register_fcm_token(
    State(state): State<AppState>,
    Json(req): Json<RegisterFcmTokenRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if req.phone.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing phone number".into(),
        ));
    }

    if req.fcm_token.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing fcmToken".into(),
        ));
    }

    // ── Get the user to verify signature ──
    let get_item_res = state
        .dynamo
        .get_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S("user".to_string()))
        .key("sk", AttributeValue::S(req.phone.clone()))
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user from DynamoDB");
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error".into())
        })?;

    let item = get_item_res.item.ok_or_else(|| {
        tracing::warn!(phone = %req.phone, "User not found");
        (StatusCode::UNAUTHORIZED, "User not found".into())
    })?;

    let signed_prekey = item
        .get("signedPreKey")
        .and_then(|v| v.as_s().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing signed pre key for user".into()))?;

    // ── Signature verification ──
    let signed_prekey_bytes: [u8; 33] = general_purpose::STANDARD
        .decode(signed_prekey)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signed pre key base64".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signed pre key length".into()))?;

    let signature_bytes: [u8; 96] = general_purpose::STANDARD
        .decode(&req.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature base64".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature length".into()))?;

    let vrf_bytes: [u8; 32] = general_purpose::STANDARD
        .decode(&req.vrf)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid vrf base64".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid vrf length".into()))?;

    // The signed message is the fcmToken string itself
    match vxeddsa_verify(&signed_prekey_bytes, req.fcm_token.as_bytes(), &signature_bytes) {
        Some(output) => {
            if output != vrf_bytes {
                tracing::warn!(phone = %req.phone, "VRF mismatch");
                return Err((StatusCode::UNAUTHORIZED, "VRF mismatch".into()));
            }
        }
        None => {
            tracing::warn!(phone = %req.phone, "Invalid signature verification");
            return Err((StatusCode::UNAUTHORIZED, "Invalid signature".into()));
        }
    }

    // ── Update fcmToken in DB ──
    state
        .dynamo
        .update_item()
        .table_name(&state.primary_table)
        .key("pk", AttributeValue::S("user".to_string()))
        .key("sk", AttributeValue::S(req.phone.clone()))
        .update_expression("SET fcmToken = :token")
        .expression_attribute_values(":token", AttributeValue::S(req.fcm_token.clone()))
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update fcmToken in DynamoDB");
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error".into())
        })?;

    Ok(StatusCode::NO_CONTENT)
}
