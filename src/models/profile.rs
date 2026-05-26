use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;

#[allow(dead_code)]
pub struct Profile {
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub picture: Option<String>,
    pub identity_key: Option<String>,
    pub signed_prekey: Option<String>,
    pub signature: Option<String>,
    pub opks: Vec<String>,
    pub created_at: Option<u64>,
    // Device fields (merged until multi-device is implemented)
    pub device_id: Option<String>,
    pub signed_device_key: Option<String>,
    pub fcm_token: Option<String>,
}

impl From<HashMap<String, AttributeValue>> for Profile {
    fn from(item: HashMap<String, AttributeValue>) -> Self {
        let opks = if let Some(AttributeValue::L(list)) = item.get("opks") {
            list.iter()
                .filter_map(|v| v.as_s().ok().cloned())
                .collect()
        } else {
            Vec::new()
        };

        Profile {
            name: item.get("name").and_then(|v| v.as_s().ok().cloned()),
            email: item.get("email").and_then(|v| v.as_s().ok().cloned()),
            phone: item.get("phone").and_then(|v| v.as_s().ok().cloned()),
            picture: item.get("picture").and_then(|v| v.as_s().ok().cloned()),
            identity_key: item.get("iKey").and_then(|v| v.as_s().ok().cloned()),
            signed_prekey: item.get("signedPreKey").and_then(|v| v.as_s().ok().cloned()),
            signature: item.get("signature").and_then(|v| v.as_s().ok().cloned()),
            opks,
            created_at: item.get("createdAt").and_then(|v| v.as_n().ok().and_then(|s| s.parse().ok())),
            device_id: item.get("deviceId").and_then(|v| v.as_s().ok().cloned()),
            signed_device_key: item.get("signedDeviceKey").and_then(|v| v.as_s().ok().cloned()),
            fcm_token: item.get("fcmToken").and_then(|v| v.as_s().ok().cloned()),
        }
    }
}
