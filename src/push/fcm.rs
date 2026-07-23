use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::provider::{PushError, PushProvider, PushToken, WakeUpPayload};

// ── Service Account key structure (from FCM JSON file) ───────────────────────

#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    token_uri: String,
}

// ── JWT Claims for Google OAuth token exchange ────────────────────────────────

#[derive(Debug, Serialize)]
struct ServiceAccountClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

// ── Token exchange response from Google OAuth ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

// ── FCM send response ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct FcmErrorDetail {
    #[serde(rename = "errorCode")]
    error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FcmError {
    details: Option<Vec<FcmErrorDetail>>,
}

#[derive(Debug, Deserialize)]
struct FcmErrorResponse {
    error: Option<FcmError>,
}

// ── FcmProvider ───────────────────────────────────────────────────────────────

/// FCM HTTP v1 push provider.
///
/// Authenticates with Google using a Service Account JSON key file, caches
/// the resulting OAuth2 bearer token, and delivers data-only wake-up
/// notifications via the FCM HTTP v1 API.
pub struct FcmProvider {
    http_client: reqwest::Client,
    project_id: String,
    client_email: String,
    private_key_pem: String,
    token_uri: String,
    /// Cached OAuth2 access token: (expiry_unix_secs, bearer_token)
    token_cache: Arc<RwLock<(u64, String)>>,
}

impl FcmProvider {
    /// Construct a new `FcmProvider` from environment variables.
    ///
    /// Required env vars:
    /// - `FCM_PROJECT_ID`
    /// - `FCM_SERVICE_ACCOUNT_KEY_PATH` — path to the service account JSON file
    pub fn from_env(http_client: reqwest::Client) -> Self {
        let project_id = std::env::var("FCM_PROJECT_ID")
            .expect("FCM_PROJECT_ID must be set");
        let key_path = std::env::var("FCM_SERVICE_ACCOUNT_KEY_PATH")
            .expect("FCM_SERVICE_ACCOUNT_KEY_PATH must be set");

        let key_json = std::fs::read_to_string(&key_path)
            .unwrap_or_else(|e| panic!("Failed to read FCM service account key at '{}': {}", key_path, e));
        let key: ServiceAccountKey = serde_json::from_str(&key_json)
            .unwrap_or_else(|e| panic!("Failed to parse FCM service account key: {}", e));

        FcmProvider {
            http_client,
            project_id,
            client_email: key.client_email,
            private_key_pem: key.private_key,
            token_uri: key.token_uri,
            token_cache: Arc::new(RwLock::new((0, String::new()))),
        }
    }

    /// Returns a valid OAuth2 bearer token, refreshing from Google if expired.
    /// Uses a write-lock with double-checked caching to prevent thundering herd.
    async fn get_access_token(&self) -> Result<String, PushError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Fast path: read lock check
        {
            let cache = self.token_cache.read().await;
            // Leave a 60-second buffer before actual expiry
            if cache.0 > now + 60 && !cache.1.is_empty() {
                return Ok(cache.1.clone());
            }
        }

        // Slow path: write lock with double-check
        let mut cache = self.token_cache.write().await;
        if cache.0 > now + 60 && !cache.1.is_empty() {
            return Ok(cache.1.clone());
        }

        tracing::info!("Refreshing FCM OAuth2 access token...");

        // Build and sign the JWT assertion
        let iat = now;
        let exp = now + 3600;
        let claims = ServiceAccountClaims {
            iss: self.client_email.clone(),
            scope: "https://www.googleapis.com/auth/firebase.messaging".to_string(),
            aud: self.token_uri.clone(),
            iat,
            exp,
        };

        let encoding_key = EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes())
            .map_err(|e| PushError::Internal(format!("Invalid FCM private key: {}", e)))?;

        let jwt = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)
            .map_err(|e| PushError::Internal(format!("Failed to sign FCM JWT: {}", e)))?;

        // Exchange the signed JWT for an OAuth2 access token
        let resp = self.http_client
            .post(&self.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| PushError::Internal(format!("FCM token exchange request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(PushError::Internal(format!(
                "FCM token exchange failed ({}): {}",
                status, body
            )));
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| PushError::Internal(format!("Failed to parse FCM token response: {}", e)))?;

        let expiry = now + token_resp.expires_in;
        let token = token_resp.access_token.clone();
        *cache = (expiry, token_resp.access_token);

        tracing::info!("FCM OAuth2 access token refreshed, valid for {}s", token_resp.expires_in);
        Ok(token)
    }

    /// Maps an FCM HTTP error response to a `PushError`.
    fn map_fcm_error(status: reqwest::StatusCode, body: &str) -> PushError {
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
            return PushError::TokenInvalid;
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return PushError::RateLimit;
        }
        // Try to extract errorCode from FCM error body
        if let Ok(err_resp) = serde_json::from_str::<FcmErrorResponse>(body) {
            if let Some(err) = err_resp.error {
                if let Some(details) = err.details {
                    for detail in details {
                        if let Some(code) = detail.error_code {
                            if code == "UNREGISTERED" || code == "INVALID_ARGUMENT" {
                                return PushError::TokenInvalid;
                            }
                        }
                    }
                }
            }
        }
        PushError::Internal(format!("FCM request failed ({}): {}", status, body))
    }
}

#[async_trait]
impl PushProvider for FcmProvider {
    async fn send(&self, token: &PushToken, payload: &WakeUpPayload) -> Result<(), PushError> {
        let access_token = self.get_access_token().await?;

        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );

        // Data-only message — zero ciphertext forwarded, preserving E2EE.
        let message = serde_json::json!({
            "message": {
                "token": token.value,
                "data": {
                    "type": "offline_message",
                    "sender_id": payload.sender_id,
                    "sender_device_id": payload.sender_device_id,
                    "topic": payload.topic,
                },
                "android": {
                    "priority": "HIGH"
                },
                "apns": {
                    "headers": {
                        "apns-priority": "10"
                    }
                }
            }
        });

        let resp = self.http_client
            .post(&fcm_url)
            .bearer_auth(&access_token)
            .json(&message)
            .send()
            .await
            .map_err(|e| PushError::Internal(format!("FCM HTTP request failed: {}", e)))?;

        if resp.status().is_success() {
            tracing::info!("FCM push sent successfully to token '{}'", &token.value[..8.min(token.value.len())]);
            return Ok(());
        }

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::error!("FCM push failed ({}): {}", status, body);
        Err(Self::map_fcm_error(status, &body))
    }
}
