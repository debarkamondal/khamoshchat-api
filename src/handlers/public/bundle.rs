use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;

use crate::{
    auth::signature::AuthenticatedUser,
    db::{keys::user_pk, primary::{get_item, query_gsi_lookup, pop_opk}},
    error::AppError,
    models::profile::Profile,
    state::AppState,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Opk {
    id: usize,
    key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyBundle {
    pub user_id: String,
    pub device_id: String,
    pub identity_key: String,
    pub signed_pre_key: String,
    pub signature: String,
    pub phone: Option<String>,
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opk: Option<Opk>,
}

pub async fn get_bundle(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
    _auth_user: AuthenticatedUser, // Requires valid signature
) -> Result<Json<PreKeyBundle>, AppError> {
    if identifier.is_empty() {
        return Err(AppError::BadRequest("Missing identifier".to_string()));
    }

    // 1. Dual-path lookup strategy
    let is_email = identifier.contains('@');
    let is_phone = identifier.starts_with('+') || identifier.chars().all(|c| c.is_digit(10));

    let mut retries = 5;
    loop {
        let profile_item_opt = if is_email || is_phone {
            // Query GSI
            query_gsi_lookup(&state, &identifier).await?
        } else {
            // Assume userId -> query base table directly
            let pk = user_pk(&identifier);
            get_item(&state, &pk, "PROFILE").await?
        };

        let item = profile_item_opt.ok_or_else(|| {
            AppError::NotFound("Requested user not found".to_string())
        })?;

        // We got the profile. Ensure we know the pk to pop OPK later.
        let pk = item.get("pk").and_then(|v| v.as_s().ok()).ok_or_else(|| {
            AppError::Internal("Database error: missing pk on user profile".to_string())
        })?.clone();

        let user_id = pk.strip_prefix("USER#").unwrap_or(&pk).to_string();

        let profile = Profile::from(item);

                let device_id = profile.device_id.unwrap_or_default();
        let identity_key = profile.identity_key.unwrap_or_default();
        let signed_pre_key = profile.signed_prekey.unwrap_or_default();
        let signature = profile.signature.unwrap_or_default();
        let phone = profile.phone;
        let picture = profile.picture;

        // Get last OPK with its index
        let mut opk = None;
        if !profile.opks.is_empty() {
            let last_index = profile.opks.len() - 1;
            let last_opk = profile.opks.last().unwrap().clone();
            
            opk = Some(Opk {
                id: last_index,
                key: last_opk.clone(),
            });

            match pop_opk(&state, &pk, "PROFILE", last_index, &last_opk).await {
                Ok(_) => {}
                Err(AppError::Conflict(_)) => {
                    if retries > 0 {
                        retries -= 1;
                        tracing::warn!("OPK conflict detected. Retrying get_bundle... Retries left: {}", retries);
                        continue;
                    } else {
                        return Err(AppError::Conflict("OPK conflict: too many retries".to_string()));
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        return Ok(Json(PreKeyBundle {
            user_id,
            device_id,
            identity_key,
            signed_pre_key,
            signature,
            phone,
            picture,
            opk,
        }));
    }
}
