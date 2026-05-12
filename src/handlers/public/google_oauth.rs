use axum::{extract::State, Json};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{
    db::{keys::pending_reg_key, temp::set_temp_json},
    error::AppError,
    models::temp_registration::TempRegistration,
    state::AppState,
};

#[derive(Deserialize)]
pub struct GoogleIdTokenRequest {
    pub id_token: String,
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
            .unwrap()
            .as_secs();
        if cache.1.is_some() && now - cache.0 < 3600 {
            jwks = cache.1.clone();
        }
    }

    if jwks.is_none() {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://www.googleapis.com/oauth2/v3/certs")
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch JWKS: {}", e);
                AppError::BadGateway(format!("Failed to fetch JWKS: {}", e))
            })?;
        let fetched_jwks: jsonwebtoken::jwk::JwkSet = resp
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse JWKS: {}", e);
                AppError::BadGateway(format!("Failed to parse JWKS: {}", e))
            })?;
        jwks = Some(fetched_jwks.clone());
        let mut cache = state.google_jwks.write().await;
        cache.0 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        cache.1 = Some(fetched_jwks);
    }

    let jwks = jwks.unwrap();
    let header = jsonwebtoken::decode_header(&req.id_token)
        .map_err(|e| {
            tracing::error!("Invalid ID token header: {}", e);
            AppError::BadRequest(format!("Invalid ID token header: {}", e))
        })?;
    let kid = header
        .kid
        .ok_or_else(|| {
            tracing::error!("Missing kid in ID token");
            AppError::BadRequest("Missing kid in ID token".to_string())
        })?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| {
            tracing::error!("Unknown kid in ID token");
            AppError::BadRequest("Unknown kid in ID token".to_string())
        })?;
    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk)
        .map_err(|e| {
            tracing::error!("Invalid JWK: {}", e);
            AppError::BadRequest(format!("Invalid JWK: {}", e))
        })?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&state.google_client_id]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

    let token_data = jsonwebtoken::decode::<GoogleIdTokenClaims>(&req.id_token, &decoding_key, &validation)
        .map_err(|e| {
            tracing::error!("Invalid ID token: {}", e);
            AppError::Unauthorized(format!("Invalid ID token: {}", e))
        })?;

    let claims = token_data.claims;
    if !claims.email_verified {
        tracing::error!("Google email not verified for {:?}", claims.email);
        return Err(AppError::Unauthorized("Google email not verified".into()));
    }

    // ── 2. Generate userId and write to Redis ──
    let user_id = Uuid::new_v4().to_string();
    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let pending_data = TempRegistration {
        email: claims.email.clone(),
        name: claims.name.clone().unwrap_or_default(),
        picture: claims.picture.clone(),
        created_at: now_millis,
    };

    let json_val = serde_json::to_string(&pending_data).map_err(|e| {
        tracing::error!("Failed to serialize pending data: {}", e);
        AppError::Internal("Serialization error".to_string())
    })?;

    let redis_key = pending_reg_key(&user_id);
    set_temp_json(&state, &redis_key, &json_val, OAUTH_TTL_SECS).await?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "userId": user_id,
        "email": claims.email,
        "name": claims.name,
        "picture": claims.picture,
    })))
}
