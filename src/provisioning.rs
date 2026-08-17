use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const PASSWORD_ENTROPY_BYTES: usize = 18;
pub const DEFAULT_BCRYPT_COST: u32 = 12;

#[derive(Debug, Error)]
pub enum UserPasswordError {
    #[error("operating-system entropy is unavailable")]
    Entropy,
    #[error("bcrypt cost must be between 10 and 16")]
    InvalidCost,
    #[error("password must contain 1 through 72 UTF-8 bytes")]
    InvalidPassword,
    #[error("bcrypt hashing failed")]
    Hash,
}

pub fn generate_initial_password() -> Result<Zeroizing<String>, UserPasswordError> {
    let mut entropy = [0_u8; PASSWORD_ENTROPY_BYTES];
    getrandom::fill(&mut entropy).map_err(|_| UserPasswordError::Entropy)?;
    let password = URL_SAFE_NO_PAD.encode(entropy.as_slice());
    entropy.zeroize();
    Ok(Zeroizing::new(password))
}

pub fn hash_password(password: &str, cost: u32) -> Result<Zeroizing<String>, UserPasswordError> {
    if !(10..=16).contains(&cost) {
        return Err(UserPasswordError::InvalidCost);
    }
    if password.is_empty() || password.len() > 72 {
        return Err(UserPasswordError::InvalidPassword);
    }
    bcrypt::hash(password, cost)
        .map(Zeroizing::new)
        .map_err(|_| UserPasswordError::Hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_independent_url_safe_144_bit_passwords() {
        let first = generate_initial_password().expect("initial password");
        let second = generate_initial_password().expect("initial password");
        assert_eq!(first.len(), 24);
        assert_ne!(first.as_str(), second.as_str());
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    #[test]
    fn hashes_only_bounded_passwords_at_supported_costs() {
        let password = generate_initial_password().expect("initial password");
        let hash = hash_password(&password, 10).expect("password hash");
        assert!(bcrypt::verify(&password, &hash).expect("valid bcrypt hash"));
        assert_eq!(&hash[..7], "$2b$10$");
        assert!(matches!(
            hash_password("", 12),
            Err(UserPasswordError::InvalidPassword)
        ));
        assert!(matches!(
            hash_password(&"x".repeat(73), 12),
            Err(UserPasswordError::InvalidPassword)
        ));
        assert!(matches!(
            hash_password("bounded", 9),
            Err(UserPasswordError::InvalidCost)
        ));
        assert!(matches!(
            hash_password("bounded", 17),
            Err(UserPasswordError::InvalidCost)
        ));
    }
}
