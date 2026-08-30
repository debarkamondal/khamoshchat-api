use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::signature::AuthenticatedUser,
    db::primary::{delete_user_account, put_user_report},
    error::AppError,
    state::AppState,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportUserRequest {
    pub reported_user_id: String,
    pub reason: String,
    #[serde(default)]
    pub messages: Vec<ReportedMessage>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ReportedMessage {
    pub id: String,
    pub content: String,
    pub sender_id: String,
    pub created_at: u64,
}

pub async fn delete_account(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<Json<serde_json::Value>, AppError> {
    delete_user_account(&state, &auth_user.user_id).await?;

    tracing::info!(user_id = %auth_user.user_id, "User account deleted successfully");

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Account deleted",
    })))
}

pub async fn report_user(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    Json(req): Json<ReportUserRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let parsed_uuid = Uuid::parse_str(&req.reported_user_id).map_err(|_| {
        AppError::BadRequest("Invalid reportedUserId format: must be UUID".to_string())
    })?;

    if parsed_uuid.get_version_num() != 4 {
        return Err(AppError::BadRequest(
            "Invalid reportedUserId format: must be UUID v4".to_string(),
        ));
    }

    if auth_user.user_id == req.reported_user_id {
        return Err(AppError::BadRequest(
            "Cannot report your own account".to_string(),
        ));
    }

    if req.reason.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Report reason cannot be empty".to_string(),
        ));
    }

    let report_id = format!("rep_{}", Uuid::new_v4());

    let messages_json = serde_json::to_string(&req.messages).map_err(|e| {
        tracing::error!("Failed to serialize report messages: {}", e);
        AppError::Internal("Internal server error".to_string())
    })?;

    put_user_report(
        &state,
        &auth_user.user_id,
        &req.reported_user_id,
        &req.reason,
        &messages_json,
    )
    .await?;

    tracing::info!(
        reporter_id = %auth_user.user_id,
        reported_id = %req.reported_user_id,
        report_id = %report_id,
        "User abuse report submitted"
    );

    Ok(Json(serde_json::json!({
        "status": "success",
        "reportId": report_id,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_user_request_deserialization() {
        let json_str = r#"{
            "reportedUserId": "c4b12d59-8f0a-4a27-a57e-399a0937a012",
            "reason": "Harassment / Spam / Abuse",
            "messages": [
                {
                    "id": "msg_01HZX87",
                    "content": "Abusive text message content",
                    "sender_id": "c4b12d59-8f0a-4a27-a57e-399a0937a012",
                    "created_at": 1756548239000
                }
            ]
        }"#;

        let req: ReportUserRequest =
            serde_json::from_str(json_str).expect("should deserialize ReportUserRequest");
        assert_eq!(req.reported_user_id, "c4b12d59-8f0a-4a27-a57e-399a0937a012");
        assert_eq!(req.reason, "Harassment / Spam / Abuse");
        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.messages[0].id, "msg_01HZX87");
        assert_eq!(req.messages[0].content, "Abusive text message content");
        assert_eq!(
            req.messages[0].sender_id,
            "c4b12d59-8f0a-4a27-a57e-399a0937a012"
        );
        assert_eq!(req.messages[0].created_at, 1756548239000);
    }
}
