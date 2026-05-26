use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct TempRegistration {
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    pub created_at: u64,
}
