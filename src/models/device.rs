use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;

#[allow(dead_code)]
pub struct Device {
    pub signed_device_key: Option<String>,
    pub fcm_token: Option<String>,
    pub created_at: Option<u64>,
}

impl From<HashMap<String, AttributeValue>> for Device {
    fn from(item: HashMap<String, AttributeValue>) -> Self {
        Device {
            signed_device_key: item.get("signedDeviceKey").and_then(|v| v.as_s().ok().cloned()),
            fcm_token: item.get("fcmToken").and_then(|v| v.as_s().ok().cloned()),
            created_at: item.get("createdAt").and_then(|v| v.as_n().ok().and_then(|s| s.parse().ok())),
        }
    }
}
