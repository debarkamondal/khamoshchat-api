use axum::{extract::State, http::StatusCode, Json};
use aws_sdk_dynamodb::types::AttributeValue;
use base64::{engine::general_purpose, Engine as _};
use libsignal_dezire::vxeddsa::vxeddsa_verify;
use rand::{rngs::OsRng, Rng};
use redis::AsyncCommands;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::AppState;

const PUBLIC_KEY_LENGTH: usize = 33;
const REGISTRATION_TTL_SECS: u64 = 600; // 10 minutes

// ─── Request types ───

#[derive(Deserialize)]
pub struct RegisterPhoneRequest {
    phone: String,
    #[serde(rename = "iKey")]
    i_key: String,
}

#[derive(Deserialize)]
pub struct RegisterOtpRequest {
    phone: String,
    #[serde(rename = "signedPreKey")]
    signed_prekey: String,
    sign: String,
    vrf: String,
    otp: u32,
    #[serde(default)]
    opks: Vec<String>,
}

// ─── POST /register/phone ───
// Generates OTP, stores phone + iKey + OTP in Redis with TTL.

pub async fn register_phone(
    State(state): State<AppState>,
    Json(req): Json<RegisterPhoneRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let otp: u32 = OsRng.gen_range(100_000..999_999);

    let redis_key = format!("reg:phone:{}", req.phone);
    let value = serde_json::json!({
        "iKey": req.i_key,
        "otp": otp,
    })
    .to_string();

    let mut conn = state.redis.clone();
    conn.set_ex::<_, _, ()>(&redis_key, &value, REGISTRATION_TTL_SECS)
        .await
        .map_err(|e| {
            tracing::error!(phone = %req.phone, error = %e, "Failed to store registration data in Redis");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis error: {e}"))
        })?;

    Ok(StatusCode::NO_CONTENT)
}

// ─── POST /register/phone/otp ───
// Verifies OTP + signature, creates final user in DynamoDB PRIMARY_TABLE.

pub async fn verify_otp(
    State(state): State<AppState>,
    Json(req): Json<RegisterOtpRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // ── Fetch registration data from Redis ──
    let redis_key = format!("reg:phone:{}", req.phone);
    let mut conn = state.redis.clone();

    let stored: Option<String> = conn
        .get(&redis_key)
        .await
        .map_err(|e| {
            tracing::error!(phone = %req.phone, error = %e, "Failed to retrieve registration data from Redis");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis error: {e}"))
        })?;

    let stored = stored.ok_or((StatusCode::NOT_FOUND, "Registration not found or expired".into()))?;

    let stored: serde_json::Value = serde_json::from_str(&stored)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Corrupt registration data".into()))?;

    // ── Verify OTP ──
    let stored_otp = stored["otp"]
        .as_u64()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Missing OTP in store".into()))?;

    if stored_otp != req.otp as u64 {
        tracing::warn!(phone = %req.phone, provided_otp = req.otp, stored_otp = stored_otp, "OTP mismatch");
        return Err((StatusCode::FORBIDDEN, "OTP mismatch".into()));
    }

    // ── Get identity key ──
    let identity_key = stored["iKey"]
        .as_str()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Missing identity key".into()))?;

    // ── Signature verification ──
    let signed_prekey_bytes: [u8; 33] = general_purpose::STANDARD
        .decode(&req.signed_prekey)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signedPreKey base64".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signedPreKey length".into()))?;

    let identity_key_bytes: [u8; 33] = general_purpose::STANDARD
        .decode(identity_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid identity key base64".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid identity key length".into()))?;

    let sign_bytes: [u8; 96] = general_purpose::STANDARD
        .decode(&req.sign)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature base64".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature length".into()))?;

    if identity_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err((StatusCode::UNAUTHORIZED, "Invalid identity key length".into()));
    }

    let vrf_bytes: [u8; 32] = general_purpose::STANDARD
        .decode(&req.vrf)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid vrf base64".into()))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid vrf length".into()))?;

    match vxeddsa_verify(&identity_key_bytes, &signed_prekey_bytes, &sign_bytes) {
        Some(output) => {
            if output != vrf_bytes {
                return Err((StatusCode::UNAUTHORIZED, "VRF mismatch".into()));
            }
        }
        None => {
            return Err((StatusCode::UNAUTHORIZED, "Invalid signature".into()));
        }
    }

    // ── Create user in DynamoDB PRIMARY_TABLE ──
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let mut item = HashMap::new();
    item.insert("pk".to_string(), AttributeValue::S("user".to_string()));
    item.insert("sk".to_string(), AttributeValue::S(req.phone.clone()));
    item.insert(
        "lsi".to_string(),
        AttributeValue::S(identity_key.to_string()),
    );
    item.insert(
        "createdAt".to_string(),
        AttributeValue::N(now.to_string()),
    );
    item.insert(
        "signedPreKey".to_string(),
        AttributeValue::S(req.signed_prekey.clone()),
    );
    item.insert(
        "signature".to_string(),
        AttributeValue::S(req.sign.clone()),
    );
    item.insert(
        "vrf".to_string(),
        AttributeValue::S(req.vrf.clone()),
    );

    let opks_attr: Vec<AttributeValue> = req
        .opks
        .iter()
        .map(|opk| AttributeValue::S(opk.clone()))
        .collect();
    item.insert("opks".to_string(), AttributeValue::L(opks_attr));

    state
        .dynamo
        .put_item()
        .table_name(&state.primary_table)
        .set_item(Some(item))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("DynamoDB put_item failed: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DynamoDB error: {e}"),
            )
        })?;

    // ── Clean up Redis entry ──
    let _: () = conn
        .del(&redis_key)
        .await
        .map_err(|e| {
            tracing::error!(phone = %req.phone, error = %e, "Failed to clean up registration data from Redis");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Redis cleanup error: {e}"))
        })?;

    Ok(StatusCode::NO_CONTENT)
}
