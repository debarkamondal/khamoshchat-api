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
pub struct Opk {
    id: usize,
    key: String,
}

#[derive(Serialize)]
pub struct PreKeyBundle {
    #[serde(rename = "identityKey")]
    identity_key: String,
    #[serde(rename = "signedPreKey")]
    signed_prekey: String,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    opk: Option<Opk>,
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

    let profile = Profile::from(item);

    let identity_key = profile.identity_key.unwrap_or_default();
    let signed_prekey = profile.signed_prekey.unwrap_or_default();
    let signature = profile.signature.unwrap_or_default();

    // Get last OPK with its index
    let mut opk = None;
    if !profile.opks.is_empty() {
        let last_index = profile.opks.len() - 1;
        let last_opk = profile.opks.last().unwrap().clone();
        
        opk = Some(Opk {
            id: last_index,
            key: last_opk,
        });

        // Fire and forget OPK pop (or await it)
        let _ = pop_opk(&state, &pk, "PROFILE", last_index).await.map_err(|e| {
            tracing::error!("Failed to pop OPK: {:?}", e);
        });
    }

    Ok(Json(PreKeyBundle {
        identity_key,
        signed_prekey,
        signature,
        opk,
    }))
}
