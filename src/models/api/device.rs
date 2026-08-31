use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceReq {
    pub state: String,
    pub state_signature: String,
    pub state_vrf: String,
    pub phone: String,
    pub signed_pre_key: String,
    pub pre_key_sign: String,
    pub pre_key_vrf: String,
    #[serde(default)]
    pub opks: Vec<String>,
    pub signed_device_key: String,
    pub dev_key_sign: String,
    pub dev_key_vrf: String,
    pub fcm_token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResp {
    pub status: String,
    pub user_id: String,
    pub device_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFcmTokenReq {
    pub device_id: String,
    pub fcm_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFcmTokenResp {
    pub status: String,
    pub message: String,
}
