use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;

use crate::push::{PushToken, PushTokenKind};

#[allow(dead_code)]
pub struct Device {
    pub signed_device_key: Option<String>,
    pub fcm_token: Option<String>,
    /// Reserved for future APNs (iOS) support.
    pub apns_token: Option<String>,
    pub created_at: Option<u64>,
}

impl Device {
    /// Returns the push token for this device, preferring FCM.
    /// Returns `None` if no push token is registered.
    pub fn push_token(&self) -> Option<PushToken> {
        if let Some(ref token) = self.fcm_token {
            return Some(PushToken {
                value: token.clone(),
                kind: PushTokenKind::Fcm,
            });
        }
        if let Some(ref token) = self.apns_token {
            return Some(PushToken {
                value: token.clone(),
                kind: PushTokenKind::Apns,
            });
        }
        None
    }
}

impl From<HashMap<String, AttributeValue>> for Device {
    fn from(item: HashMap<String, AttributeValue>) -> Self {
        Device {
            signed_device_key: item
                .get("signedDeviceKey")
                .and_then(|v| v.as_s().ok().cloned()),
            fcm_token: item.get("fcmToken").and_then(|v| v.as_s().ok().cloned()),
            apns_token: item.get("apnsToken").and_then(|v| v.as_s().ok().cloned()),
            created_at: item
                .get("createdAt")
                .and_then(|v| v.as_n().ok().and_then(|s| s.parse().ok())),
        }
    }
}
