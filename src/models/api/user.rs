use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountResp {
    pub status: String,
    pub message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportUserReq {
    pub reported_user_id: String,
    pub reason: String,
    #[serde(default)]
    pub messages: Vec<ReportedMessage>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportUserResp {
    pub status: String,
    pub report_id: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ReportedMessage {
    pub id: String,
    pub content: String,
    pub sender_id: String,
    pub created_at: u64,
}
