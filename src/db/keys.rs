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
