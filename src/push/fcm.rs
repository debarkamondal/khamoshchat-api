use crate::error::AppError;
use serde_json::Value;

pub async fn send_push(token: &str, payload: &Value) -> Result<(), AppError> {
    tracing::info!(
        "STUB: Sending push notification to FCM token '{}' with payload: {:?}",
        token,
        payload
    );
    // In the future, integrate with FCM/APN API here.
    Ok(())
}
