use async_trait::async_trait;

use super::provider::{PushError, PushProvider, PushToken, WakeUpPayload};

/// APNs (Apple Push Notification service) provider skeleton.
///
/// This struct satisfies the `PushProvider` trait so the abstraction compiles
/// and `PushTokenKind::Apns` is a valid variant from day one.
/// Actual HTTP/2 APNs delivery will be implemented in a future milestone.
#[allow(dead_code)] // Intentional stub — APNs delivery implemented in a future PR
pub struct ApnsProvider;

#[async_trait]
impl PushProvider for ApnsProvider {
    async fn send(&self, _token: &PushToken, _payload: &WakeUpPayload) -> Result<(), PushError> {
        Err(PushError::Internal(
            "APNs push delivery is not yet implemented — use FCM for Android devices".to_string(),
        ))
    }
}
