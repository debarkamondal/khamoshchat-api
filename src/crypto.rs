use crate::error::AppError;
use base64::{engine::general_purpose, Engine as _};
use libsignal_dezire::vxeddsa::vxeddsa_verify;

pub const PUBLIC_KEY_LENGTH: usize = 33;
pub const SIGNATURE_LENGTH: usize = 96;
pub const VRF_LENGTH: usize = 32;

pub fn decode_b64_key(
    base64_str: &str,
    expected_len: usize,
    name: &str,
) -> Result<Vec<u8>, AppError> {
    let bytes = general_purpose::STANDARD
        .decode(base64_str)
        .map_err(|e| AppError::BadRequest(format!("Invalid {} base64: {}", name, e)))?;

    if bytes.len() != expected_len {
        return Err(AppError::BadRequest(format!("Invalid {} length", name)));
    }

    Ok(bytes)
}

pub fn verify_signed_signature(
    identity_key_b64: &str,
    target_key_b64: &str,
    signature_b64: &str,
    vrf_b64: &str,
    field_name: &str,
) -> Result<(), AppError> {
    let identity_key_bytes = decode_b64_key(identity_key_b64, PUBLIC_KEY_LENGTH, "iKey")?;
    let target_key_bytes = decode_b64_key(target_key_b64, PUBLIC_KEY_LENGTH, field_name)?;
    let signature_bytes = decode_b64_key(signature_b64, SIGNATURE_LENGTH, "signature")?;
    let expected_vrf_bytes = decode_b64_key(vrf_b64, VRF_LENGTH, "vrf")?;

    let i_key: [u8; 33] = identity_key_bytes.try_into().unwrap();
    let target_key: [u8; 33] = target_key_bytes.try_into().unwrap();
    let sig: [u8; 96] = signature_bytes.try_into().unwrap();

    match vxeddsa_verify(&i_key, &target_key, &sig) {
        Some(vrf) => {
            if vrf != expected_vrf_bytes.as_slice() {
                return Err(AppError::Unauthorized(format!(
                    "VRF mismatch for {}",
                    field_name
                )));
            }
            Ok(())
        }
        None => Err(AppError::Unauthorized(format!(
            "Invalid signature for {}",
            field_name
        ))),
    }
}

pub fn verify_signature(
    public_key_bytes: &[u8; 33],
    message: &[u8],
    signature_bytes: &[u8; 96],
) -> Result<[u8; 32], AppError> {
    match vxeddsa_verify(public_key_bytes, message, signature_bytes) {
        Some(vrf) => Ok(vrf),
        None => Err(AppError::Unauthorized("Invalid signature".into())),
    }
}
