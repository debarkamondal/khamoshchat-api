use async_trait::async_trait;

/// The platform-specific token used to address a device.
#[derive(Debug, Clone)]
pub struct PushToken {
    pub value: String,
    #[allow(dead_code)] // Used when APNs dispatch is implemented
    pub kind: PushTokenKind,
}

/// Which push notification platform this token belongs to.
#[derive(Debug, Clone, PartialEq)]
pub enum PushTokenKind {
    Fcm,
    Apns,
}

/// Data-only wake-up payload sent to a device.
/// Never contains message ciphertext — only routing metadata
/// so the device knows to reconnect to MQTT and fetch messages.
#[derive(Debug, Clone)]
pub struct WakeUpPayload {
    pub sender_id: String,
    pub sender_device_id: String,
    pub topic: String,
}

/// Errors a push provider can return, mapped to upstream business logic.
#[derive(Debug)]
pub enum PushError {
    /// Device token is no longer valid (e.g. app uninstalled).
    /// Caller should remove this token from the database.
    TokenInvalid,
    /// Provider is rate-limiting requests.
    RateLimit,
    /// Any other transient or provider-side error.
    Internal(String),
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushError::TokenInvalid => write!(f, "Push token is invalid or unregistered"),
            PushError::RateLimit => write!(f, "Push provider is rate-limiting requests"),
            PushError::Internal(msg) => write!(f, "Push provider internal error: {}", msg),
        }
    }
}

/// Common interface for all push notification providers (FCM, APNs, ...).
/// Adding a new provider requires only implementing this trait and
/// wiring it up in `AppState::new()` -- no handler changes needed.
#[async_trait]
pub trait PushProvider: Send + Sync {
    async fn send(&self, token: &PushToken, payload: &WakeUpPayload) -> Result<(), PushError>;
}
