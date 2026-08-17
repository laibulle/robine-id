use crate::{
    configuration::{Snapshot, User},
    database::SigningKey,
};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(flatten)]
    extra: &'a Map<String, Value>,
}

pub struct IdTokenInput<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub audience: &'a str,
    pub nonce: Option<&'a str>,
    pub claims: &'a Map<String, Value>,
    pub now: i64,
    pub lifetime: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct VerifiedIdToken {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
}

pub fn issue_id_token(
    key: &SigningKey,
    input: &IdTokenInput<'_>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    header.typ = Some("JWT".to_owned());
    jsonwebtoken::encode(
        &header,
        &IdTokenClaims {
            iss: input.issuer,
            sub: input.subject,
            aud: input.audience,
            iat: input.now,
            exp: input.now + input.lifetime,
            nonce: input.nonce,
            extra: input.claims,
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes())?,
    )
}

pub fn verify_id_token(
    token: &str,
    key: &SigningKey,
    expected_issuer: &str,
    clock_skew_seconds: u64,
) -> Result<VerifiedIdToken, jsonwebtoken::errors::Error> {
    let header = decode_header(token)?;
    if header.alg != Algorithm::RS256 || header.kid.as_deref() != Some(&key.kid) {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm,
        ));
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[expected_issuer]);
    validation.validate_aud = false;
    validation.leeway = clock_skew_seconds;
    decode::<VerifiedIdToken>(
        token,
        &DecodingKey::from_rsa_components(&key.modulus, &key.exponent)?,
        &validation,
    )
    .map(|decoded| decoded.claims)
}

pub fn mapped_claims(snapshot: &Snapshot, user: &User, scopes: &[String]) -> Map<String, Value> {
    snapshot
        .configuration
        .claims
        .iter()
        .filter(|(claim, mapping)| {
            !matches!(
                claim.as_str(),
                "iss" | "sub" | "aud" | "iat" | "exp" | "nonce"
            ) && scopes.contains(&mapping.scope)
        })
        .filter_map(|(claim, mapping)| {
            let value = match mapping.source.as_str() {
                "name" => user.name.clone().map(Value::String),
                "email" => user.email.clone().map(Value::String),
                source => user.claims.get(source).cloned(),
            }?;
            Some((claim.clone(), value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{DecodingKey, Validation, decode};
    use rand_core::OsRng;
    use rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey, LineEnding},
        traits::PublicKeyParts,
    };

    #[test]
    fn signs_an_rs256_token_verifiable_with_the_published_key() {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key");
        let public = private.to_public_key();
        let key = SigningKey {
            kid: "test-key".to_owned(),
            private_key_pem: private
                .to_pkcs8_pem(LineEnding::LF)
                .expect("PEM")
                .to_string(),
            modulus: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            exponent: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        };
        let now = chrono::Utc::now().timestamp();
        let token = issue_id_token(
            &key,
            &IdTokenInput {
                issuer: "https://id.example/default",
                subject: "user-1",
                audience: "client-1",
                nonce: Some("nonce"),
                claims: &Map::new(),
                now,
                lifetime: 300,
            },
        )
        .expect("ID token");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://id.example/default"]);
        validation.set_audience(&["client-1"]);
        let decoded = decode::<Value>(
            &token,
            &DecodingKey::from_rsa_components(&key.modulus, &key.exponent).expect("public key"),
            &validation,
        )
        .expect("valid signature");

        assert_eq!(decoded.header.kid.as_deref(), Some("test-key"));
        assert_eq!(decoded.claims["sub"], "user-1");
        assert_eq!(decoded.claims["nonce"], "nonce");

        let verified = verify_id_token(&token, &key, "https://id.example/default", 30)
            .expect("verified ID token");
        assert_eq!(verified.sub, "user-1");
        assert_eq!(verified.aud, "client-1");
    }
}
