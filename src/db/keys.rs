pub fn user_pk(user_id: &str) -> String {
    format!("USER#{}", user_id)
}

pub fn profile_sk() -> String {
    "PROFILE".to_string()
}

pub fn device_sk(device_id: &str) -> String {
    format!("DEVICE#{}", device_id)
}

pub fn pending_reg_key(user_id: &str) -> String {
    format!("reg:pending:{}", user_id)
}

pub fn email_lookup_pk(email: &str) -> String {
    format!("EMAIL#{}", email.to_lowercase().trim())
}

pub fn phone_lookup_pk(phone: &str) -> String {
    format!("PHONE#{}", phone.trim())
}

pub fn lookup_sk() -> String {
    "PTR".to_string()
}
