use axum::{
    extract::FromRequestParts,
    http::request::Parts,
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    crypto::verify_signature,
    db::{keys::user_pk, primary::get_item},
    error::AppError,
    models::profile::Profile,
    state::AppState,
};

pub struct AuthenticatedUser {
    pub user_id: String,
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let user_id = parts
            .headers
            .get("X-User-Id")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("Missing X-User-Id header".to_string()))?;

        let timestamp_str = parts
            .headers
            .get("X-Timestamp")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("Missing X-Timestamp header".to_string()))?;

        let signature_b64 = parts
            .headers
            .get("X-Signature")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("Missing X-Signature header".to_string()))?;

        // let vrf_b64 = parts
        //     .headers
        //     .get("X-Vrf")
        //     .and_then(|h| h.to_str().ok())
        //     .ok_or_else(|| AppError::Unauthorized("Missing X-Vrf header".to_string()))?;

        // 1. Timestamp validation (prevent replay attacks)
        let timestamp: u64 = timestamp_str.parse().map_err(|_| {
            AppError::Unauthorized("Invalid timestamp format".to_string())
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Allow +/- 5 minutes drift
        let drift = if now > timestamp {
            now - timestamp
        } else {
            timestamp - now
        };

        if drift > 300_000 {
            return Err(AppError::Unauthorized("Timestamp expired or too far in the future".to_string()));
        }

        // 2. Fetch User Profile
        let pk = user_pk(user_id);
        let sk = "PROFILE";
        let item_opt = get_item(state, &pk, sk).await?;
        
        let item = item_opt.ok_or_else(|| {
            AppError::Unauthorized("User not found".to_string())
        })?;

        let profile = Profile::from(item);

        let signed_prekey_b64 = profile.signed_prekey.ok_or_else(|| {
            AppError::Unauthorized("Missing signed_prekey for user".to_string())
        })?;

        // let stored_vrf_b64 = profile.vrf.ok_or_else(|| {
        //     AppError::Unauthorized("Missing vrf for user".to_string())
        // })?;

        // 3. Verify Signature
        // The signed payload is: userId + timestamp
        let payload = format!("{}{}", user_id, timestamp_str);
        
        let signed_prekey_bytes = crate::crypto::decode_b64_key(&signed_prekey_b64, crate::crypto::PUBLIC_KEY_LENGTH, "signedPreKey")?;
        let signature_bytes = crate::crypto::decode_b64_key(signature_b64, crate::crypto::SIGNATURE_LENGTH, "signature")?;
        // let expected_vrf_bytes = crate::crypto::decode_b64_key(vrf_b64, crate::crypto::VRF_LENGTH, "vrf")?;
        
        let public_key: [u8; 33] = signed_prekey_bytes.try_into().unwrap();
        let sig: [u8; 96] = signature_bytes.try_into().unwrap();

        match verify_signature(&public_key, payload.as_bytes(), &sig) {
            Ok(output_vrf) => {
                // VRF matching could be added here if needed, comparing output_vrf with expected_vrf_bytes
                // if output_vrf != expected_vrf_bytes {
                //    return Err(AppError::Unauthorized("VRF mismatch".to_string()));
                // }
                Ok(AuthenticatedUser {
                    user_id: user_id.to_string(),
                })
            }
            Err(_) => Err(AppError::Unauthorized("Invalid signature".to_string())),
        }
    }
}
