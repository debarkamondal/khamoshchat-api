use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct TempRegistration {
    pub user_id: String,
    pub i_key: String,
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    pub created_at: u64,
}
