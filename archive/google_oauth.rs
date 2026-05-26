use aws_sdk_dynamodb::types::AttributeValue;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Redirect,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use libsignal_dezire::vxeddsa::vxeddsa_verify;
use redis::AsyncCommands;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::AppState;

const OAUTH_TTL_SECS: u64 = 600; // 10 minutes
const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v3/userinfo";

// ─── Request types ───

#[derive(Deserialize)]
pub struct GoogleOAuthInitRequest {
    phone: String,
    #[serde(rename = "iKey")]
    i_key: String,
    #[serde(rename = "signedPreKey")]
    signed_prekey: String,
    sign: String,
    vrf: String,
    #[serde(default)]
    opks: Vec<String>,
}

#[derive(Deserialize)]
pub struct GoogleOAuthCallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    email: String,
    email_verified: Option<bool>,
    picture: Option<String>,
}

// ─── POST /register/google_oauth/init ───
// Takes phone + all crypto keys, stores in Redis, redirects to Google consent.

pub async fn google_oauth_init(
    State(state): State<AppState>,
    Json(req): Json<GoogleOAuthInitRequest>,
) -> Result<Redirect, (StatusCode, String)> {
    // ── Verify signed prekey against identity key ──
    let identity_key_bytes: [u8; 33] = general_purpose::STANDARD
        .decode(&req.i_key)
        .map_err(|e| {
            tracing::error!("google_oauth_init: Invalid iKey base64: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid iKey base64".into())
        })?
        .try_into()
        .map_err(|_| {
            tracing::error!("google_oauth_init: Invalid iKey length");
            (StatusCode::BAD_REQUEST, "Invalid iKey length".into())
        })?;

    let signed_prekey_bytes: [u8; 33] = general_purpose::STANDARD
        .decode(&req.signed_prekey)
        .map_err(|e| {
            tracing::error!("google_oauth_init: Invalid signedPreKey base64: {}", e);
            (
                StatusCode::BAD_REQUEST,
                "Invalid signedPreKey base64".into(),
            )
        })?
        .try_into()
        .map_err(|_| {
            tracing::error!("google_oauth_init: Invalid signedPreKey length");
            (
                StatusCode::BAD_REQUEST,
                "Invalid signedPreKey length".into(),
            )
        })?;

    let sign_bytes: [u8; 96] = general_purpose::STANDARD
        .decode(&req.sign)
        .map_err(|e| {
            tracing::error!("google_oauth_init: Invalid signature base64: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid signature base64".into())
        })?
        .try_into()
        .map_err(|_| {
            tracing::error!("google_oauth_init: Invalid signature length");
            (StatusCode::BAD_REQUEST, "Invalid signature length".into())
        })?;

    let vrf_bytes: [u8; 32] = general_purpose::STANDARD
        .decode(&req.vrf)
        .map_err(|e| {
            tracing::error!("google_oauth_init: Invalid vrf base64: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid vrf base64".into())
        })?
        .try_into()
        .map_err(|_| {
            tracing::error!("google_oauth_init: Invalid vrf length");
            (StatusCode::BAD_REQUEST, "Invalid vrf length".into())
        })?;

    match vxeddsa_verify(&identity_key_bytes, &signed_prekey_bytes, &sign_bytes) {
        Some(output) => {
            // if output != vrf_bytes {
            //     return Err((StatusCode::UNAUTHORIZED, "VRF mismatch".into()));
            // }
        }
        None => {
            tracing::error!("google_oauth_init: Invalid signature verification failed");
            return Err((StatusCode::UNAUTHORIZED, "Invalid signature".into()));
        }
    }

    // Generate unique state token
    let oauth_state = uuid::Uuid::new_v4().to_string();

    // Store all user data in Redis keyed by state
    let redis_key = format!("reg:google_oauth:{}", oauth_state);
    let value = serde_json::json!({
        "phone": req.phone,
        "iKey": req.i_key,
        "signedPreKey": req.signed_prekey,
        "sign": req.sign,
        "vrf": req.vrf,
        "opks": req.opks,
    })
    .to_string();

    let mut conn = state.redis.clone();
    conn.set_ex::<_, _, ()>(&redis_key, &value, OAUTH_TTL_SECS)
        .await
        .map_err(|e| {
            tracing::error!("google_oauth_init: Redis set error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Redis error: {e}"),
            )
        })?;

    // Build Google OAuth authorization URL
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope=email%20profile&state={}&access_type=offline&prompt=consent",
        GOOGLE_AUTH_URL,
        state.google_client_id,
        urlencoding::encode(&state.google_redirect_uri),
        oauth_state,
    );

    Ok(Redirect::temporary(&auth_url))
}

// ─── GET /register/google_oauth/callback ───
// Google redirects here. Exchanges code for token, retrieves user info,
// creates user in DynamoDB with stored crypto keys from Redis.

pub async fn google_oauth_callback(
    State(state): State<AppState>,
    Query(params): Query<GoogleOAuthCallbackQuery>,
) -> Result<Redirect, (StatusCode, String)> {
    // ── Retrieve stored keys from Redis ──
    let redis_key = format!("reg:google_oauth:{}", params.state);
    let mut conn = state.redis.clone();

    let stored: Option<String> = conn.get(&redis_key).await.map_err(|e| {
        tracing::error!("google_oauth_callback: Redis get error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Redis error: {e}"),
        )
    })?;

    let stored = stored.ok_or_else(|| {
        tracing::error!("google_oauth_callback: Invalid or expired OAuth state param");
        (
            StatusCode::BAD_REQUEST,
            "Invalid or expired OAuth state".into(),
        )
    })?;

    let stored: serde_json::Value = serde_json::from_str(&stored).map_err(|e| {
        tracing::error!("google_oauth_callback: Json parse error for stored data: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Corrupt OAuth data".into(),
        )
    })?;

    // ── Exchange authorization code for access token ──
    let http_client = reqwest::Client::new();

    let token_resp = http_client
        .post(GOOGLE_TOKEN_URL)
        .form(&[
            ("code", params.code.as_str()),
            ("client_id", state.google_client_id.as_str()),
            ("client_secret", state.google_client_secret.as_str()),
            ("redirect_uri", state.google_redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| {
            tracing::error!("google_oauth_callback: Google token exchange failed: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                format!("Google token exchange failed: {e}"),
            )
        })?;

    if !token_resp.status().is_success() {
        let body = token_resp.text().await.unwrap_or_default();
        tracing::error!("google_oauth_callback: Google token error response: {}", body);
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Google token error: {body}"),
        ));
    }

    let token_data: GoogleTokenResponse = token_resp.json().await.map_err(|e| {
        tracing::error!("google_oauth_callback: Invalid token response json: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            format!("Invalid token response: {e}"),
        )
    })?;

    // ── Fetch user info from Google ──
    let user_resp = http_client
        .get(GOOGLE_USERINFO_URL)
        .bearer_auth(&token_data.access_token)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("google_oauth_callback: Google userinfo request failed: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                format!("Google userinfo failed: {e}"),
            )
        })?;

    let user_info: GoogleUserInfo = user_resp.json().await.map_err(|e| {
        tracing::error!("google_oauth_callback: Invalid userinfo response json: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            format!("Invalid userinfo response: {e}"),
        )
    })?;

    if user_info.email_verified != Some(true) {
        tracing::error!("google_oauth_callback: Google email not verified for {:?}", user_info.email);
        return Err((StatusCode::FORBIDDEN, "Google email not verified".into()));
    }

    // ── Create user in DynamoDB PRIMARY_TABLE ──
    let phone = stored["phone"].as_str().ok_or_else(|| {
        tracing::error!("google_oauth_callback: Missing phone in store");
        (StatusCode::INTERNAL_SERVER_ERROR, "Missing phone in store".into())
    })?;
    let identity_key = stored["iKey"].as_str().ok_or_else(|| {
        tracing::error!("google_oauth_callback: Missing iKey in store");
        (StatusCode::INTERNAL_SERVER_ERROR, "Missing iKey in store".into())
    })?;
    let signed_prekey = stored["signedPreKey"].as_str().ok_or_else(|| {
        tracing::error!("google_oauth_callback: Missing signedPreKey in store");
        (StatusCode::INTERNAL_SERVER_ERROR, "Missing signedPreKey in store".into())
    })?;
    let sign = stored["sign"].as_str().ok_or_else(|| {
        tracing::error!("google_oauth_callback: Missing sign in store");
        (StatusCode::INTERNAL_SERVER_ERROR, "Missing sign in store".into())
    })?;
    let vrf = stored["vrf"].as_str().ok_or_else(|| {
        tracing::error!("google_oauth_callback: Missing vrf in store");
        (StatusCode::INTERNAL_SERVER_ERROR, "Missing vrf in store".into())
    })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let mut item = HashMap::new();
    item.insert("pk".to_string(), AttributeValue::S("user".to_string()));
    item.insert("sk".to_string(), AttributeValue::S(phone.to_string()));
    item.insert(
        "lsi".to_string(),
        AttributeValue::S(identity_key.to_string()),
    );
    item.insert("createdAt".to_string(), AttributeValue::N(now.to_string()));
    item.insert(
        "signedPreKey".to_string(),
        AttributeValue::S(signed_prekey.to_string()),
    );
    item.insert("signature".to_string(), AttributeValue::S(sign.to_string()));
    item.insert("vrf".to_string(), AttributeValue::S(vrf.to_string()));
    item.insert("email".to_string(), AttributeValue::S(user_info.email));
    if let Some(pic) = user_info.picture {
        item.insert("image".to_string(), AttributeValue::S(pic));
    }

    // OPKs
    let opks: Vec<AttributeValue> = stored["opks"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| AttributeValue::S(s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    item.insert("opks".to_string(), AttributeValue::L(opks));

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

    // ── Clean up Redis ──
    let _: () = conn.del(&redis_key).await.map_err(|e| {
        tracing::error!("google_oauth_callback: Redis cleanup error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Redis cleanup error: {e}"),
        )
    })?;

    // ── Redirect back to the app ──
    // TODO: Replace with actual deep link / app callback URL
    Ok(Redirect::temporary("/oauth/success"))
}

#[derive(Deserialize)]
pub struct GoogleIdTokenRequest {
    pub phone: String,
    #[serde(rename = "iKey")]
    pub i_key: String,
    #[serde(rename = "signedPreKey")]
    pub signed_prekey: String,
    pub sign: String,
    pub vrf: String,
    #[serde(default)]
    pub opks: Vec<String>,
    pub id_token: String,
}

#[derive(Deserialize)]
struct GoogleIdTokenClaims {
    email: String,
    email_verified: bool,
    picture: Option<String>,
}

// ─── POST /register/google_oauth/id_token ───
// Takes phone + crypto keys + id_token. Verifies signature, validates id_token
// locally, then creates/updates the user.
pub async fn google_oauth_id_token(
    State(state): State<AppState>,
    Json(req): Json<GoogleIdTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // ── 1. Verify signed prekey against identity key ──
    let identity_key_bytes: [u8; 33] = general_purpose::STANDARD
        .decode(&req.i_key)
        .map_err(|e| {
            tracing::error!("google_oauth_id_token: Invalid iKey base64: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid iKey base64".into())
        })?
        .try_into()
        .map_err(|_| {
            tracing::error!("google_oauth_id_token: Invalid iKey length");
            (StatusCode::BAD_REQUEST, "Invalid iKey length".into())
        })?;

    let signed_prekey_bytes: [u8; 33] = general_purpose::STANDARD
        .decode(&req.signed_prekey)
        .map_err(|e| {
            tracing::error!("google_oauth_id_token: Invalid signedPreKey base64: {}", e);
            (
                StatusCode::BAD_REQUEST,
                "Invalid signedPreKey base64".into(),
            )
        })?
        .try_into()
        .map_err(|_| {
            tracing::error!("google_oauth_id_token: Invalid signedPreKey length");
            (
                StatusCode::BAD_REQUEST,
                "Invalid signedPreKey length".into(),
            )
        })?;

    let sign_bytes: [u8; 96] = general_purpose::STANDARD
        .decode(&req.sign)
        .map_err(|e| {
            tracing::error!("google_oauth_id_token: Invalid signature base64: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid signature base64".into())
        })?
        .try_into()
        .map_err(|_| {
            tracing::error!("google_oauth_id_token: Invalid signature length");
            (StatusCode::BAD_REQUEST, "Invalid signature length".into())
        })?;

    let vrf_bytes: [u8; 32] = general_purpose::STANDARD
        .decode(&req.vrf)
        .map_err(|e| {
            tracing::error!("google_oauth_id_token: Invalid vrf base64: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid vrf base64".into())
        })?
        .try_into()
        .map_err(|_| {
            tracing::error!("google_oauth_id_token: Invalid vrf length");
            (StatusCode::BAD_REQUEST, "Invalid vrf length".into())
        })?;

    match vxeddsa_verify(&identity_key_bytes, &signed_prekey_bytes, &sign_bytes) {
        Some(_) => {}
        None => {
            tracing::error!("google_oauth_id_token: Invalid signature verification failed");
            return Err((StatusCode::UNAUTHORIZED, "Invalid signature".into()));
        }
    }

    // ── 2. JWT Verification (Google id_token) ──
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
                tracing::error!("google_oauth_id_token: Failed to fetch JWKS: {}", e);
                (StatusCode::BAD_GATEWAY, format!("Failed to fetch JWKS: {}", e))
            })?;
        let fetched_jwks: jsonwebtoken::jwk::JwkSet = resp
            .json()
            .await
            .map_err(|e| {
                tracing::error!("google_oauth_id_token: Failed to parse JWKS: {}", e);
                (StatusCode::BAD_GATEWAY, format!("Failed to parse JWKS: {}", e))
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
            tracing::error!("google_oauth_id_token: Invalid ID token header: {}", e);
            (StatusCode::BAD_REQUEST, format!("Invalid ID token header: {}", e))
        })?;
    let kid = header
        .kid
        .ok_or_else(|| {
            tracing::error!("google_oauth_id_token: Missing kid in ID token");
            (StatusCode::BAD_REQUEST, "Missing kid in ID token".to_string())
        })?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| {
            tracing::error!("google_oauth_id_token: Unknown kid in ID token");
            (StatusCode::BAD_REQUEST, "Unknown kid in ID token".to_string())
        })?;
    let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk)
        .map_err(|e| {
            tracing::error!("google_oauth_id_token: Invalid JWK: {}", e);
            (StatusCode::BAD_REQUEST, format!("Invalid JWK: {}", e))
        })?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[&state.google_client_id]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

    let token_data = jsonwebtoken::decode::<GoogleIdTokenClaims>(&req.id_token, &decoding_key, &validation)
        .map_err(|e| {
            tracing::error!("google_oauth_id_token: Invalid ID token: {}", e);
            (StatusCode::UNAUTHORIZED, format!("Invalid ID token: {}", e))
        })?;

    let claims = token_data.claims;
    if !claims.email_verified {
        tracing::error!("google_oauth_id_token: Google email not verified for {:?}", claims.email);
        return Err((StatusCode::FORBIDDEN, "Google email not verified".into()));
    }

    // ── 3. Create user in DynamoDB PRIMARY_TABLE ──
    let phone = req.phone;
    let identity_key = req.i_key;
    let signed_prekey = req.signed_prekey;
    let sign = req.sign;
    let vrf = req.vrf;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let mut item = HashMap::new();
    item.insert("pk".to_string(), AttributeValue::S("user".to_string()));
    item.insert("sk".to_string(), AttributeValue::S(phone.to_string()));
    item.insert(
        "lsi".to_string(),
        AttributeValue::S(identity_key.to_string()),
    );
    item.insert("createdAt".to_string(), AttributeValue::N(now.to_string()));
    item.insert(
        "signedPreKey".to_string(),
        AttributeValue::S(signed_prekey.to_string()),
    );
    item.insert("signature".to_string(), AttributeValue::S(sign.to_string()));
    item.insert("vrf".to_string(), AttributeValue::S(vrf.to_string()));
    item.insert("email".to_string(), AttributeValue::S(claims.email.clone()));
    
    if let Some(pic) = claims.picture {
        item.insert("image".to_string(), AttributeValue::S(pic));
    }

    // OPKs
    let opks: Vec<AttributeValue> = req
        .opks
        .into_iter()
        .map(|s| AttributeValue::S(s))
        .collect();
    if !opks.is_empty() {
        item.insert("opks".to_string(), AttributeValue::L(opks));
    }

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

    Ok(Json(serde_json::json!({
        "status": "success",
        "email": claims.email
    })))
}
