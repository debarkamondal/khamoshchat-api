use axum::{extract::State, Json};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{
    db::{
        keys::{email_lookup_pk, lookup_sk, pending_reg_key},
        primary::get_item,
        temp::set_temp_json,
    },
    error::AppError,
    models::temp_registration::TempRegistration,
    state::AppState,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleIdTokenRequest {
    pub id_token: String,
    pub i_key: String,
}

#[derive(Deserialize)]
struct GoogleIdTokenClaims {
    email: String,
    email_verified: bool,
    picture: Option<String>,
    name: Option<String>,
}

const OAUTH_TTL_SECS: u64 = 600; // 10 minutes

pub async fn verify_id_token(
    State(state): State<AppState>,
    Json(req): Json<GoogleIdTokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // ── 1. JWT Verification (Google id_token) ──
    let mut jwks = None;
    {
        let cache = state.google_jwks.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if cache.1.is_some() && now < cache.0 {
            jwks = cache.1.clone();
        }
    }

    if jwks.is_none() {
        // Double-checked locking: acquire write lock, then re-check before fetching.
        // This ensures only one concurrent request fires the outbound JWKS HTTP call
        // when the cache expires ("thundering herd" prevention).
        let mut cache = state.google_jwks.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if cache.1.is_some() && now < cache.0 {
            // Another concurrent request already refreshed the cache while we waited
            // for the write lock — reuse it.
            jwks = cache.1.clone();
        } else {
            // Cache is still stale — we are the one request that fetches it.
            // Use the shared HTTP client to reuse the existing TLS connection pool.
            let resp = state
                .http_client
                .get("https://www.googleapis.com/oauth2/v3/certs")
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("Failed to fetch JWKS: {}", e);
                    AppError::BadGateway("Failed to fetch JWKS".into())
                })?;

            let max_age_secs = resp
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| {
                    s.split(',').find_map(|part| {
                        let part = part.trim();
                        part.strip_prefix("max-age=")
                            .and_then(|val| val.trim().parse::<u64>().ok())
                    })
                })
                .unwrap_or(3600)
                .clamp(300, 86400);

            let fetched_jwks: jsonwebtoken::jwk::JwkSet = resp.json().await.map_err(|e| {
                tracing::error!("Failed to parse JWKS: {}", e);
                AppError::BadGateway("Failed to parse JWKS".into())
            })?;
            jwks = Some(fetched_jwks.clone());
            cache.0 = now + max_age_secs;
            cache.1 = Some(fetched_jwks);
            tracing::info!(ttl_secs = max_age_secs, "Refreshed Google JWKS cache");
        }
    }

    let jwks = jwks.ok_or_else(|| AppError::Internal("JWKS unavailable".to_string()))?;
    let header = jsonwebtoken::decode_header(&req.id_token).map_err(|e| {
        tracing::error!("Invalid ID token header: {}", e);
        AppError::BadRequest("Invalid ID token header".to_string())
    })?;
    let kid = header.kid.ok_or_else(|| {
        tracing::error!("Missing kid in ID token");
        AppError::BadRequest("Missing kid in ID token".to_string())
    })?;

    let jwk = jwks.find(&kid).ok_or_else(|| {
        tracing::error!("Unknown kid in ID token: {}", kid);
        AppError::BadRequest("Unknown kid in ID token".to_string())
    })?;
    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|e| {
        tracing::error!("Invalid JWK: {}", e);
        AppError::BadRequest("Invalid JWK".to_string())
    })?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&state.google_client_id]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

    let token_data =
        jsonwebtoken::decode::<GoogleIdTokenClaims>(&req.id_token, &decoding_key, &validation)
            .map_err(|e| {
                tracing::error!("Invalid ID token: {}", e);
                AppError::Unauthorized("Invalid ID token".to_string())
            })?;

    let claims = token_data.claims;
    if !claims.email_verified {
        tracing::error!("Google email not verified for {:?}", claims.email);
        return Err(AppError::Unauthorized("Google email not verified".into()));
    }

    // ── 2. Reuse existing userId if email pointer exists for claims.email, otherwise generate new userId ──
    let email_pk = email_lookup_pk(&claims.email);
    let existing_pointer = get_item(&state, &email_pk, lookup_sk()).await?;
    let user_id = if let Some(ref item) = existing_pointer {
        item.get("userId")
            .and_then(|v| v.as_s().ok())
            .map(|id| id.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string())
    } else {
        Uuid::new_v4().to_string()
    };

    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let pending_data = TempRegistration {
        user_id: user_id.clone(),
        i_key: req.i_key,
        email: claims.email.clone(),
        name: claims.name.clone().unwrap_or_default(),
        picture: claims.picture.clone(),
        created_at: now_millis,
    };

    let json_val = serde_json::to_string(&pending_data).map_err(|e| {
        tracing::error!("Failed to serialize pending data: {}", e);
        AppError::Internal("Serialization error".to_string())
    })?;

    let state_token = Uuid::new_v4().to_string();
    let redis_key = pending_reg_key(&state_token);
    set_temp_json(&state, &redis_key, &json_val, OAUTH_TTL_SECS).await?;

    tracing::info!(user_id = %user_id, email = %claims.email, "Google ID token verified and pending registration cached");

    Ok(Json(serde_json::json!({
        "status": "success",
        "userId": user_id,
        "state": state_token,
        "email": claims.email,
        "name": claims.name,
        "picture": claims.picture,
    })))
}
