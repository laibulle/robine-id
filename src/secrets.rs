use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const DEPLOYMENT_SECRET_BYTES: usize = 48;

#[derive(Debug, Error)]
pub enum SecretGenerationError {
    #[error("operating-system entropy is unavailable")]
    Entropy,
}

/// Generates deployment-specific wrapping material suitable for
/// `KEY_ENCRYPTION_SECRET`.
///
/// The encoded value contains 384 bits of operating-system entropy and only
/// uses characters that can be copied directly into an environment file.
pub fn generate_key_encryption_secret() -> Result<Zeroizing<String>, SecretGenerationError> {
    generate_deployment_secret()
}

/// Generates an independent URL-safe PostgreSQL password for release Compose.
pub fn generate_database_password() -> Result<Zeroizing<String>, SecretGenerationError> {
    generate_deployment_secret()
}

fn generate_deployment_secret() -> Result<Zeroizing<String>, SecretGenerationError> {
    let mut entropy = [0_u8; DEPLOYMENT_SECRET_BYTES];
    getrandom::fill(&mut entropy).map_err(|_| SecretGenerationError::Entropy)?;
    let secret = URL_SAFE_NO_PAD.encode(entropy.as_slice());
    entropy.zeroize();
    Ok(Zeroizing::new(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_independent_env_safe_384_bit_secrets() {
        let first = generate_key_encryption_secret().expect("key encryption secret");
        let second = generate_database_password().expect("database password");

        assert_eq!(first.len(), 64);
        assert_ne!(first.as_str(), second.as_str());
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(first.as_bytes())
                .expect("canonical base64url secret")
                .len(),
            DEPLOYMENT_SECRET_BYTES
        );
    }
}
