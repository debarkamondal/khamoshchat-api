use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Opk {
    pub id: usize,
    pub key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyBundleResp {
    pub user_id: String,
    pub device_id: String,
    pub identity_key: String,
    pub spk_id: u32,
    pub signed_pre_key: String,
    pub signature: String,
    pub phone: Option<String>,
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opk: Option<Opk>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncBundleResp {
    pub user_id: String,
    pub identity_key: String,
    pub picture: Option<String>,
    pub display_name: Option<String>,
}
