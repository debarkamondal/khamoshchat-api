use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use aws_sdk_dynamodb::types::{AttributeValue, KeysAndAttributes};
use base64::{engine::general_purpose, Engine as _};
use libsignal_dezire::vxeddsa::vxeddsa_verify;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct BundleRequest {
    phone: String,
    signature: String,
    vrf: String,
}

#[derive(Serialize)]
pub struct Opk {
    id: usize,
    key: String,
}

#[derive(Serialize)]
pub struct PreKeyBundle {
    #[serde(rename = "identityKey")]
    identity_key: String,
    #[serde(rename = "signedPreKey")]
    signed_prekey: String,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    opk: Option<Opk>,
}

/// POST /bundle/:phone
///
/// Verifies the requester's signature and returns the requested user's PreKeyBundle.
pub async fn get_bundle(
    State(state): State<AppState>,
    Path(requested_phone): Path<String>,
    Json(req): Json<BundleRequest>,
) -> Result<Json<PreKeyBundle>, (StatusCode, String)> {
    if requested_phone.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing requested phone number".into(),
        ));
    }

    // ── Batch get both users from DynamoDB ──
    let mut keys = Vec::new();

    let mut requester_key = HashMap::new();
    requester_key.insert("pk".to_string(), AttributeValue::S("user".to_string()));
    requester_key.insert("sk".to_string(), AttributeValue::S(req.phone.clone()));
    keys.push(requester_key);

    let mut requested_key = HashMap::new();
    requested_key.insert("pk".to_string(), AttributeValue::S("user".to_string()));
    requested_key.insert(
        "sk".to_string(),
        AttributeValue::S(requested_phone.clone()),
    );
    keys.push(requested_key);

    let mut request_items = HashMap::new();
    request_items.insert(
        state.primary_table.clone(),
        KeysAndAttributes::builder()
            .set_keys(Some(keys))
            .build()
            .unwrap(),
    );

    let batch_result = state
        .dynamo
        .batch_get_item()
        .set_request_items(Some(request_items))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let responses = batch_result.responses.unwrap_or_default();
    let items = responses
        .get(&state.primary_table)
        .cloned()
        .unwrap_or_default();

    // ── Find requester & requested items ──
    let requester_item = items
        .iter()
        .find(|item| item.get("sk").and_then(|v| v.as_s().ok()) == Some(&req.phone));
    let requested_item = items
        .iter()
        .find(|item| item.get("sk").and_then(|v| v.as_s().ok()) == Some(&requested_phone));

    let requester_item = requester_item.ok_or((
        StatusCode::NOT_FOUND,
        "Requester not found".into(),
    ))?;

    // ── Signature verification ──
    let signed_prekey = requester_item
        .get("signedPreKey")
        .and_then(|v| v.as_s().ok())
        .ok_or((StatusCode::BAD_REQUEST, "Missing signed pre key".into()))?;

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

    match vxeddsa_verify(&signed_prekey_bytes, requested_phone.as_bytes(), &signature_bytes) {
        Some(output) => {
            if output != vrf_bytes {
                return Err((StatusCode::UNAUTHORIZED, "VRF mismatch".into()));
            }
        }
        None => {
            return Err((StatusCode::UNAUTHORIZED, "Invalid signature".into()));
        }
    }

    // ── Return requested user's bundle ──
    let item = requested_item.ok_or((
        StatusCode::NOT_FOUND,
        "Requested user not found".into(),
    ))?;

    let identity_key = item
        .get("lsi")
        .and_then(|v| v.as_s().ok())
        .cloned()
        .unwrap_or_default();
    let signed_prekey = item
        .get("signedPreKey")
        .and_then(|v| v.as_s().ok())
        .cloned()
        .unwrap_or_default();
    let signature = item
        .get("signature")
        .and_then(|v| v.as_s().ok())
        .cloned()
        .unwrap_or_default();

    // Get last OPK with its index
    let opk_list = item.get("opks").and_then(|v| v.as_l().ok());
    let opk = match opk_list {
        Some(list) if !list.is_empty() => {
            let last_index = list.len() - 1;
            let last_opk = list.last().and_then(|v| v.as_s().ok()).cloned();
            last_opk.map(|key| Opk {
                id: last_index,
                key,
            })
        }
        _ => None,
    };

    Ok(Json(PreKeyBundle {
        identity_key,
        signed_prekey,
        signature,
        opk,
    }))
}
