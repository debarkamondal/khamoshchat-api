pub fn user_pk(user_id: &str) -> String {
    format!("USER#{}", user_id)
}

pub fn profile_sk() -> &'static str {
    "PROFILE"
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

pub fn normalize_phone(phone: &str) -> String {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    let no_leading_zeros = digits.trim_start_matches('0');
    if no_leading_zeros.len() > 10 {
        no_leading_zeros[no_leading_zeros.len() - 10..].to_string()
    } else {
        no_leading_zeros.to_string()
    }
}

pub fn phone_lookup_pk(phone: &str) -> String {
    format!("PHONE#{}", normalize_phone(phone))
}

pub fn lookup_sk() -> &'static str {
    "PTR"
}

pub fn reporter_pk(reporter_id: &str) -> String {
    format!("REPORTER#{}", reporter_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_pk() {
        assert_eq!(user_pk("user-123"), "USER#user-123");
    }

    #[test]
    fn test_reporter_pk() {
        assert_eq!(reporter_pk("reporter-789"), "REPORTER#reporter-789");
    }

    #[test]
    fn test_device_sk() {
        assert_eq!(device_sk("dev-456"), "DEVICE#dev-456");
    }

    #[test]
    fn test_pending_reg_key() {
        assert_eq!(pending_reg_key("user-123"), "reg:pending:user-123");
    }

    #[test]
    fn test_email_lookup_pk() {
        assert_eq!(
            email_lookup_pk(" Test.User@Example.COM "),
            "EMAIL#test.user@example.com"
        );
    }

    #[test]
    fn test_phone_lookup_pk() {
        assert_eq!(phone_lookup_pk("  +1234567890  "), "PHONE#1234567890");
        assert_eq!(phone_lookup_pk("  +44 7123 456789  "), "PHONE#7123456789");
    }

    #[test]
    fn test_static_sks() {
        assert_eq!(profile_sk(), "PROFILE");
        assert_eq!(lookup_sk(), "PTR");
    }
}
