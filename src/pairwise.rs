use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::configuration::{Client, Snapshot};

const MINIMUM_SALT_BYTES: usize = 32;
const DOMAIN_SEPARATOR: &[u8] = b"robine-id pairwise subject v1\0";

#[derive(Debug, Error)]
pub enum PairwiseSubjectError {
    #[error("pairwise subject sector is unavailable")]
    MissingSector,
    #[error("pairwise subject salt is unavailable or shorter than 32 bytes")]
    MissingSalt,
}

pub fn external_subject(
    snapshot: &Snapshot,
    issuer: &str,
    client: &Client,
    internal_subject: &str,
) -> Result<String, PairwiseSubjectError> {
    if client.subject_type != "pairwise"
        || snapshot
            .configured_user_for_issuer_url(issuer, internal_subject)
            .is_none()
    {
        return Ok(internal_subject.to_owned());
    }
    let sector = client
        .pairwise_sector()
        .ok_or(PairwiseSubjectError::MissingSector)?;
    let salt = configured_salt(snapshot).ok_or(PairwiseSubjectError::MissingSalt)?;
    derive_pairwise_subject(
        &salt,
        issuer.trim_end_matches('/'),
        &sector,
        internal_subject,
    )
}

fn configured_salt(snapshot: &Snapshot) -> Option<Zeroizing<String>> {
    snapshot
        .configuration
        .pairwise_subject_salt_reference
        .as_ref()
        .and_then(|reference| match reference {
            serde_json::Value::Object(reference)
                if reference
                    .get("provider")
                    .and_then(serde_json::Value::as_str)
                    == Some("env") =>
            {
                reference
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|key| std::env::var(key).ok())
                    .filter(|secret| secret.len() >= MINIMUM_SALT_BYTES)
                    .map(Zeroizing::new)
            }
            _ => None,
        })
}

fn derive_pairwise_subject(
    salt: &str,
    issuer: &str,
    sector: &str,
    internal_subject: &str,
) -> Result<String, PairwiseSubjectError> {
    if salt.len() < MINIMUM_SALT_BYTES {
        return Err(PairwiseSubjectError::MissingSalt);
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(salt.as_bytes()).expect("HMAC accepts keys of every length");
    mac.update(DOMAIN_SEPARATOR);
    for value in [
        issuer.as_bytes(),
        sector.as_bytes(),
        internal_subject.as_bytes(),
    ] {
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value);
    }
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn derivation_is_stable_and_bound_to_issuer_sector_and_user() {
        let first = derive_pairwise_subject(SALT, "https://id.example", "app.example", "alice")
            .expect("pairwise subject");
        assert_eq!(first.len(), 43);
        assert_eq!(
            first,
            derive_pairwise_subject(SALT, "https://id.example", "app.example", "alice")
                .expect("stable pairwise subject")
        );
        assert_ne!(
            first,
            derive_pairwise_subject(SALT, "https://id.example", "other.example", "alice")
                .expect("other sector")
        );
        assert_ne!(
            first,
            derive_pairwise_subject(SALT, "https://other-id.example", "app.example", "alice")
                .expect("other issuer")
        );
        assert_ne!(
            first,
            derive_pairwise_subject(SALT, "https://id.example", "app.example", "bob")
                .expect("other user")
        );
    }

    #[test]
    fn rejects_short_salts() {
        assert!(matches!(
            derive_pairwise_subject("too-short", "https://id.example", "app.example", "alice"),
            Err(PairwiseSubjectError::MissingSalt)
        ));
    }

    #[test]
    fn external_subject_preserves_public_and_service_subjects() {
        let mut snapshot = Snapshot::load().expect("development configuration");
        let client = snapshot.configuration.clients[0].clone();
        let user = snapshot.configuration.users[0].id.clone();
        let issuer = snapshot.configuration.issuers[0].url.clone();
        assert_eq!(
            external_subject(&snapshot, &issuer, &client, &user).expect("public subject"),
            user
        );

        let mut pairwise = client;
        pairwise.subject_type = "pairwise".to_owned();
        pairwise.sector_identifier = Some("app.example".to_owned());
        snapshot.configuration.pairwise_subject_salt_reference = Some(serde_json::json!({
            "provider": "env",
            "key": "PATH"
        }));
        let pairwise_subject =
            external_subject(&snapshot, &issuer, &pairwise, &user).expect("pairwise subject");
        assert_ne!(pairwise_subject, user);
        snapshot.configuration.users[0].enabled = false;
        assert!(snapshot.user(&user).is_none());
        assert_eq!(
            external_subject(&snapshot, &issuer, &pairwise, &user)
                .expect("disabled identity keeps its pairwise subject"),
            pairwise_subject
        );
        let mut same_sector = pairwise.clone();
        same_sector.id = "other-client-in-sector".to_owned();
        assert_eq!(
            external_subject(&snapshot, &issuer, &same_sector, &user,)
                .expect("same-sector subject"),
            pairwise_subject
        );
        let mut other_sector = pairwise.clone();
        other_sector.sector_identifier = Some("other.example".to_owned());
        assert_ne!(
            external_subject(&snapshot, &issuer, &other_sector, &user,)
                .expect("other-sector subject"),
            pairwise_subject
        );
        assert_eq!(
            external_subject(
                &snapshot,
                "https://id.example/default",
                &pairwise,
                "service-client",
            )
            .expect("service subject"),
            "service-client"
        );

        snapshot.configuration.pairwise_subject_salt_reference = Some(serde_json::json!({
            "provider": "env",
            "key": "ROBINE_ID_PAIRWISE_TEST_MISSING"
        }));
        assert!(matches!(
            external_subject(&snapshot, &issuer, &pairwise, &user,),
            Err(PairwiseSubjectError::MissingSalt)
        ));
    }
}
