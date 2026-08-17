use crate::{
    configuration::{ClientJwkSet, Snapshot, User},
    database::{PublicSigningKey, SigningKey},
    protocol::AuthorizationRequest,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, EllipticCurve, KeyAlgorithm, PublicKeyUse, ThumbprintHash},
};
use rsa::{BigUint, RsaPublicKey, traits::PublicKeyParts};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub use crate::configuration::{MFA_ACR, PASSWORD_ACR};

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    at_hash: Option<&'a str>,
    acr: &'static str,
    amr: Vec<&'static str>,
    #[serde(flatten)]
    extra: &'a Map<String, Value>,
}

#[derive(Serialize)]
struct AccessTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    jti: &'a str,
    client_id: &'a str,
    scope: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amr: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<AccessTokenConfirmation<'a>>,
    #[serde(flatten)]
    extra: &'a Map<String, Value>,
}

#[derive(Serialize)]
struct AccessTokenConfirmation<'a> {
    jkt: &'a str,
}

#[derive(Serialize)]
struct AuthorizationResponseClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a str>,
}

pub struct IdTokenInput<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub audience: &'a str,
    pub nonce: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub mfa_verified: bool,
    pub at_hash: Option<&'a str>,
    pub claims: &'a Map<String, Value>,
    pub now: i64,
    pub lifetime: i64,
}

pub struct AccessTokenInput<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub audience: &'a str,
    pub client_id: &'a str,
    pub scope: &'a str,
    pub jti: &'a str,
    pub auth_time: Option<i64>,
    pub mfa_verified: bool,
    pub dpop_jkt: Option<&'a str>,
    pub claims: &'a Map<String, Value>,
    pub now: i64,
    pub lifetime: i64,
}

pub struct AuthorizationResponseInput<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub code: Option<&'a str>,
    pub error: Option<&'a str>,
    pub error_description: Option<&'a str>,
    pub state: Option<&'a str>,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum JwtAudience {
    One(String),
    Many(Vec<String>),
}

#[derive(Clone, Debug, Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    aud: JwtAudience,
    exp: i64,
    iat: i64,
    jti: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedClientAssertion {
    pub jti: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
struct AuthorizationRequestObjectClaims {
    iss: String,
    aud: JwtAudience,
    exp: i64,
    iat: i64,
    jti: String,
    #[serde(flatten)]
    request: AuthorizationRequest,
}

#[derive(Clone, Debug)]
pub struct VerifiedAuthorizationRequestObject {
    pub request: AuthorizationRequest,
    pub jti: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDpopProof {
    pub jkt: String,
    pub jti: String,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DpopProofValidationError;

#[derive(Debug, Deserialize)]
struct DpopProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
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
            auth_time: input.auth_time,
            at_hash: input.at_hash,
            acr: if input.mfa_verified {
                MFA_ACR
            } else {
                PASSWORD_ACR
            },
            amr: if input.mfa_verified {
                vec!["pwd", "otp"]
            } else {
                vec!["pwd"]
            },
            extra: input.claims,
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes())?,
    )
}

pub fn issue_access_token(
    key: &SigningKey,
    input: &AccessTokenInput<'_>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    header.typ = Some("at+jwt".to_owned());
    jsonwebtoken::encode(
        &header,
        &AccessTokenClaims {
            iss: input.issuer,
            sub: input.subject,
            aud: input.audience,
            exp: input.now + input.lifetime,
            iat: input.now,
            jti: input.jti,
            client_id: input.client_id,
            scope: input.scope,
            auth_time: input.auth_time,
            acr: input.auth_time.map(|_| {
                if input.mfa_verified {
                    MFA_ACR
                } else {
                    PASSWORD_ACR
                }
            }),
            amr: input.auth_time.map(|_| {
                if input.mfa_verified {
                    vec!["pwd", "otp"]
                } else {
                    vec!["pwd"]
                }
            }),
            cnf: input.dpop_jkt.map(|jkt| AccessTokenConfirmation { jkt }),
            extra: input.claims,
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes())?,
    )
}

pub fn issue_authorization_response(
    key: &SigningKey,
    input: &AuthorizationResponseInput<'_>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    header.typ = Some("oauth-authz-resp+jwt".to_owned());
    jsonwebtoken::encode(
        &header,
        &AuthorizationResponseClaims {
            iss: input.issuer,
            aud: input.audience,
            iat: input.now,
            exp: input.now + input.lifetime,
            code: input.code,
            error: input.error,
            error_description: input.error_description,
            state: input.state,
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes())?,
    )
}

pub fn access_token_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
}

pub fn dpop_access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

pub fn verify_dpop_proof(
    proof: &str,
    expected_method: &str,
    expected_uri: &str,
    expected_access_token: Option<&str>,
    clock_skew_seconds: u64,
    now: i64,
) -> Result<VerifiedDpopProof, DpopProofValidationError> {
    if proof.is_empty() || proof.len() > 12 * 1024 {
        return Err(DpopProofValidationError);
    }
    let mut segments = proof.split('.');
    let encoded_header = segments.next().ok_or(DpopProofValidationError)?;
    if segments.next().is_none() || segments.next().is_none() || segments.next().is_some() {
        return Err(DpopProofValidationError);
    }
    let raw_header = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| DpopProofValidationError)?;
    if raw_header.len() > 4_096 {
        return Err(DpopProofValidationError);
    }
    let raw_header: Value =
        serde_json::from_slice(&raw_header).map_err(|_| DpopProofValidationError)?;
    let jwk_object = raw_header
        .get("jwk")
        .and_then(Value::as_object)
        .ok_or(DpopProofValidationError)?;
    if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        .iter()
        .any(|parameter| jwk_object.contains_key(*parameter))
    {
        return Err(DpopProofValidationError);
    }

    let header = decode_header(proof).map_err(|_| DpopProofValidationError)?;
    if header.typ.as_deref() != Some("dpop+jwt")
        || !matches!(header.alg, Algorithm::ES256 | Algorithm::RS256)
        || header.jku.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some()
    {
        return Err(DpopProofValidationError);
    }
    let jwk = header.jwk.as_ref().ok_or(DpopProofValidationError)?;
    if jwk.common.public_key_use.is_some()
        && jwk.common.public_key_use != Some(PublicKeyUse::Signature)
    {
        return Err(DpopProofValidationError);
    }
    if !matches!(
        (header.alg, jwk.common.key_algorithm),
        (_, None)
            | (Algorithm::ES256, Some(KeyAlgorithm::ES256))
            | (Algorithm::RS256, Some(KeyAlgorithm::RS256))
    ) {
        return Err(DpopProofValidationError);
    }
    match (&header.alg, &jwk.algorithm) {
        (Algorithm::ES256, AlgorithmParameters::EllipticCurve(parameters))
            if parameters.curve == EllipticCurve::P256 =>
        {
            let x = URL_SAFE_NO_PAD
                .decode(&parameters.x)
                .map_err(|_| DpopProofValidationError)?;
            let y = URL_SAFE_NO_PAD
                .decode(&parameters.y)
                .map_err(|_| DpopProofValidationError)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(DpopProofValidationError);
            }
        }
        (Algorithm::RS256, AlgorithmParameters::RSA(parameters)) => {
            let modulus = URL_SAFE_NO_PAD
                .decode(&parameters.n)
                .map_err(|_| DpopProofValidationError)?;
            let exponent = URL_SAFE_NO_PAD
                .decode(&parameters.e)
                .map_err(|_| DpopProofValidationError)?;
            let key = RsaPublicKey::new(
                BigUint::from_bytes_be(&modulus),
                BigUint::from_bytes_be(&exponent),
            )
            .map_err(|_| DpopProofValidationError)?;
            if key.n().bits() < 2_048 {
                return Err(DpopProofValidationError);
            }
        }
        _ => return Err(DpopProofValidationError),
    }

    let mut validation = Validation::new(header.alg);
    validation.required_spec_claims.clear();
    validation.set_required_spec_claims(&["jti", "htm", "htu", "iat"]);
    validation.validate_exp = false;
    validation.validate_aud = false;
    let claims = decode::<DpopProofClaims>(
        proof,
        &DecodingKey::from_jwk(jwk).map_err(|_| DpopProofValidationError)?,
        &validation,
    )
    .map_err(|_| DpopProofValidationError)?
    .claims;
    let htu = url::Url::parse(&claims.htu).map_err(|_| DpopProofValidationError)?;
    let expected_htu = url::Url::parse(expected_uri).map_err(|_| DpopProofValidationError)?;
    let skew = i64::try_from(clock_skew_seconds).unwrap_or(i64::MAX);
    if claims.jti.is_empty()
        || claims.jti.len() > 256
        || claims.htm != expected_method
        || htu != expected_htu
        || htu.query().is_some()
        || htu.fragment().is_some()
        || claims.iat > now.saturating_add(skew)
        || claims.iat < now.saturating_sub(300).saturating_sub(skew)
        || claims
            .nonce
            .as_deref()
            .is_some_and(|nonce| !valid_dpop_nonce(nonce))
    {
        return Err(DpopProofValidationError);
    }
    match expected_access_token {
        Some(access_token)
            if claims.ath.as_deref() != Some(dpop_access_token_hash(access_token).as_str()) =>
        {
            return Err(DpopProofValidationError);
        }
        _ => {}
    }
    Ok(VerifiedDpopProof {
        jkt: jwk.thumbprint(ThumbprintHash::SHA256),
        jti: claims.jti,
        nonce: claims.nonce,
    })
}

fn valid_dpop_nonce(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len() <= 512
        && nonce.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

pub fn verify_id_token(
    token: &str,
    key: &PublicSigningKey,
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

pub fn verify_client_assertion(
    assertion: &str,
    jwks: &ClientJwkSet,
    client_id: &str,
    expected_audience: &str,
    clock_skew_seconds: u64,
    now: i64,
) -> Result<VerifiedClientAssertion, jsonwebtoken::errors::Error> {
    if assertion.is_empty() || assertion.len() > 8_192 {
        return Err(invalid_token_error());
    }
    let header = decode_header(assertion)?;
    if header.alg != Algorithm::RS256 {
        return Err(invalid_token_error());
    }
    let kid = header.kid.as_deref().ok_or_else(invalid_token_error)?;
    let key = jwks
        .keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or_else(invalid_token_error)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[client_id]);
    validation.validate_aud = false;
    validation.leeway = clock_skew_seconds;
    validation.set_required_spec_claims(&["exp", "iat", "iss", "sub"]);
    let claims = decode::<ClientAssertionClaims>(
        assertion,
        &DecodingKey::from_rsa_components(&key.n, &key.e)?,
        &validation,
    )?
    .claims;
    let audience_matches = match &claims.aud {
        JwtAudience::One(audience) => audience == expected_audience,
        JwtAudience::Many(audiences) => {
            !audiences.is_empty()
                && audiences
                    .iter()
                    .any(|audience| audience == expected_audience)
        }
    };
    let skew = i64::try_from(clock_skew_seconds).unwrap_or(i64::MAX);
    if claims.iss != client_id
        || claims.sub != client_id
        || !audience_matches
        || claims.jti.is_empty()
        || claims.jti.len() > 256
        || claims.exp <= claims.iat
        || claims.exp.saturating_sub(claims.iat) > 300
        || claims.iat > now.saturating_add(skew)
        || claims.iat < now.saturating_sub(300).saturating_sub(skew)
    {
        return Err(invalid_token_error());
    }
    Ok(VerifiedClientAssertion {
        jti: claims.jti,
        expires_at: claims.exp,
    })
}

pub fn verify_authorization_request_object(
    request_object: &str,
    jwks: &ClientJwkSet,
    client_id: &str,
    expected_issuer: &str,
    clock_skew_seconds: u64,
    now: i64,
) -> Result<VerifiedAuthorizationRequestObject, jsonwebtoken::errors::Error> {
    if request_object.is_empty() || request_object.len() > 12 * 1024 {
        return Err(invalid_token_error());
    }
    let header = decode_header(request_object)?;
    if header.alg != Algorithm::RS256 {
        return Err(invalid_token_error());
    }
    let kid = header.kid.as_deref().ok_or_else(invalid_token_error)?;
    let key = jwks
        .keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or_else(invalid_token_error)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[client_id]);
    validation.validate_aud = false;
    validation.leeway = clock_skew_seconds;
    validation.set_required_spec_claims(&["exp", "iat", "iss"]);
    let mut claims = decode::<AuthorizationRequestObjectClaims>(
        request_object,
        &DecodingKey::from_rsa_components(&key.n, &key.e)?,
        &validation,
    )?
    .claims;
    let audience_matches = match &claims.aud {
        JwtAudience::One(audience) => audience == expected_issuer,
        JwtAudience::Many(audiences) => {
            !audiences.is_empty() && audiences.iter().any(|audience| audience == expected_issuer)
        }
    };
    let skew = i64::try_from(clock_skew_seconds).unwrap_or(i64::MAX);
    if claims.iss != client_id
        || !audience_matches
        || claims.jti.is_empty()
        || claims.jti.len() > 256
        || claims.exp <= claims.iat
        || claims.exp.saturating_sub(claims.iat) > 300
        || claims.iat > now.saturating_add(skew)
        || claims.iat < now.saturating_sub(300).saturating_sub(skew)
        || (!claims.request.client_id.is_empty() && claims.request.client_id != client_id)
        || claims.request.request_object.is_some()
        || claims.request.request_uri.is_some()
    {
        return Err(invalid_token_error());
    }
    claims.request.client_id = client_id.to_owned();
    claims.request.request_object = None;
    Ok(VerifiedAuthorizationRequestObject {
        request: claims.request.normalize_empty_optional_parameters(),
        jti: claims.jti,
        expires_at: claims.exp,
    })
}

fn invalid_token_error() -> jsonwebtoken::errors::Error {
    jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
}

pub fn mapped_claims(snapshot: &Snapshot, user: &User, scopes: &[String]) -> Map<String, Value> {
    snapshot
        .configuration
        .claims
        .iter()
        .filter(|(claim, mapping)| {
            !matches!(
                claim.as_str(),
                "iss"
                    | "sub"
                    | "aud"
                    | "iat"
                    | "exp"
                    | "nbf"
                    | "jti"
                    | "nonce"
                    | "auth_time"
                    | "at_hash"
                    | "c_hash"
                    | "acr"
                    | "amr"
                    | "azp"
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{DecodingKey, Validation, decode};
    use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
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
                auth_time: Some(now),
                mfa_verified: false,
                at_hash: Some(&access_token_hash("SlAV32hkKG")),
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
        assert_eq!(decoded.claims["auth_time"], now);
        assert_eq!(decoded.claims["at_hash"], "rXH7QWVTZnXYCou_6Vdpfg");
        assert_eq!(decoded.claims["acr"], PASSWORD_ACR);
        assert_eq!(decoded.claims["amr"], serde_json::json!(["pwd"]));

        let mfa_token = issue_id_token(
            &key,
            &IdTokenInput {
                issuer: "https://id.example/default",
                subject: "user-1",
                audience: "client-1",
                nonce: None,
                auth_time: Some(now),
                mfa_verified: true,
                at_hash: None,
                claims: &Map::new(),
                now,
                lifetime: 300,
            },
        )
        .expect("MFA ID token");
        let mfa_decoded = decode::<Value>(
            &mfa_token,
            &DecodingKey::from_rsa_components(&key.modulus, &key.exponent).expect("public key"),
            &validation,
        )
        .expect("valid MFA signature");
        assert_eq!(mfa_decoded.claims["acr"], MFA_ACR);
        assert_eq!(mfa_decoded.claims["amr"], serde_json::json!(["pwd", "otp"]));

        let verification_key = PublicSigningKey {
            kid: key.kid.clone(),
            modulus: key.modulus.clone(),
            exponent: key.exponent.clone(),
        };
        let verified = verify_id_token(&token, &verification_key, "https://id.example/default", 30)
            .expect("verified ID token");
        assert_eq!(verified.sub, "user-1");
        assert_eq!(verified.aud, "client-1");
        assert_eq!(access_token_hash("SlAV32hkKG"), "rXH7QWVTZnXYCou_6Vdpfg");
    }

    #[test]
    fn signs_an_rfc_9068_access_token_with_resource_and_dpop_confirmation() {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key");
        let public = private.to_public_key();
        let key = SigningKey {
            kid: "access-key".to_owned(),
            private_key_pem: private
                .to_pkcs8_pem(LineEnding::LF)
                .expect("PEM")
                .to_string(),
            modulus: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            exponent: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        };
        let now = chrono::Utc::now().timestamp();
        let claims = Map::from_iter([("tenant".to_owned(), serde_json::json!("base59"))]);
        let token = issue_access_token(
            &key,
            &AccessTokenInput {
                issuer: "https://id.example/default",
                subject: "user-1",
                audience: "https://api.example",
                client_id: "client-1",
                scope: "openid profile",
                jti: "access-token-id",
                auth_time: Some(now - 60),
                mfa_verified: true,
                dpop_jkt: Some("proof-thumbprint"),
                claims: &claims,
                now,
                lifetime: 300,
            },
        )
        .expect("access token");

        let header = decode_header(&token).expect("access token header");
        assert_eq!(header.kid.as_deref(), Some("access-key"));
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://id.example/default"]);
        validation.set_audience(&["https://api.example"]);
        let decoded = decode::<Value>(
            &token,
            &DecodingKey::from_rsa_components(&key.modulus, &key.exponent).expect("public key"),
            &validation,
        )
        .expect("valid access token signature");

        assert_eq!(decoded.claims["sub"], "user-1");
        assert_eq!(decoded.claims["client_id"], "client-1");
        assert_eq!(decoded.claims["scope"], "openid profile");
        assert_eq!(decoded.claims["jti"], "access-token-id");
        assert_eq!(decoded.claims["cnf"]["jkt"], "proof-thumbprint");
        assert_eq!(decoded.claims["auth_time"], now - 60);
        assert_eq!(decoded.claims["acr"], MFA_ACR);
        assert_eq!(decoded.claims["amr"], serde_json::json!(["pwd", "otp"]));
        assert_eq!(decoded.claims["tenant"], "base59");
        assert_eq!(decoded.claims["iat"], now);
        assert_eq!(decoded.claims["exp"], now + 300);

        let machine_token = issue_access_token(
            &key,
            &AccessTokenInput {
                issuer: "https://id.example/default",
                subject: "service-client",
                audience: "https://api.example",
                client_id: "service-client",
                scope: "service.read",
                jti: "machine-access-token-id",
                auth_time: None,
                mfa_verified: false,
                dpop_jkt: None,
                claims: &Map::new(),
                now,
                lifetime: 300,
            },
        )
        .expect("machine access token");
        let machine = decode::<Value>(
            &machine_token,
            &DecodingKey::from_rsa_components(&key.modulus, &key.exponent).expect("public key"),
            &validation,
        )
        .expect("valid machine access token signature");
        assert!(machine.claims.get("auth_time").is_none());
        assert!(machine.claims.get("acr").is_none());
        assert!(machine.claims.get("amr").is_none());
    }

    #[test]
    fn signs_a_short_lived_jarm_response_for_the_client() {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key");
        let public = private.to_public_key();
        let key = SigningKey {
            kid: "jarm-key".to_owned(),
            private_key_pem: private
                .to_pkcs8_pem(LineEnding::LF)
                .expect("PEM")
                .to_string(),
            modulus: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            exponent: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        };
        let now = chrono::Utc::now().timestamp();
        let response = issue_authorization_response(
            &key,
            &AuthorizationResponseInput {
                issuer: "https://id.example/default",
                audience: "web-client",
                code: Some("one-time-code"),
                error: None,
                error_description: None,
                state: Some("client-state"),
                now,
                lifetime: 60,
            },
        )
        .expect("JARM response");
        let header = decode_header(&response).expect("JARM header");
        assert_eq!(header.kid.as_deref(), Some("jarm-key"));
        assert_eq!(header.typ.as_deref(), Some("oauth-authz-resp+jwt"));
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://id.example/default"]);
        validation.set_audience(&["web-client"]);
        let decoded = decode::<Value>(
            &response,
            &DecodingKey::from_rsa_components(&key.modulus, &key.exponent).expect("public key"),
            &validation,
        )
        .expect("valid JARM signature");

        assert_eq!(decoded.claims["code"], "one-time-code");
        assert_eq!(decoded.claims["state"], "client-state");
        assert_eq!(decoded.claims["iat"], now);
        assert_eq!(decoded.claims["exp"], now + 60);
        assert!(decoded.claims.get("error").is_none());
    }

    #[test]
    fn verifies_a_bounded_endpoint_specific_client_assertion() {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key");
        let public = private.to_public_key();
        let private_key = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("PEM")
            .to_string();
        let jwks = ClientJwkSet {
            keys: vec![crate::configuration::ClientJwk {
                kty: "RSA".to_owned(),
                kid: "client-key".to_owned(),
                use_: Some("sig".to_owned()),
                alg: Some("RS256".to_owned()),
                n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
            }],
        };
        let now = chrono::Utc::now().timestamp();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("client-key".to_owned());
        let assertion = jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "iss": "service-client",
                "sub": "service-client",
                "aud": "https://id.example/default/token",
                "iat": now,
                "exp": now + 120,
                "jti": "single-use-assertion"
            }),
            &EncodingKey::from_rsa_pem(private_key.as_bytes()).expect("private key"),
        )
        .expect("assertion");

        assert_eq!(
            verify_client_assertion(
                &assertion,
                &jwks,
                "service-client",
                "https://id.example/default/token",
                30,
                now,
            )
            .expect("verified assertion"),
            VerifiedClientAssertion {
                jti: "single-use-assertion".to_owned(),
                expires_at: now + 120,
            }
        );
        assert!(
            verify_client_assertion(
                &assertion,
                &jwks,
                "service-client",
                "https://id.example/default/introspect",
                30,
                now,
            )
            .is_err()
        );
    }

    #[test]
    fn verifies_a_signed_authorization_request_object() {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key");
        let public = private.to_public_key();
        let private_key = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("PEM")
            .to_string();
        let jwks = ClientJwkSet {
            keys: vec![crate::configuration::ClientJwk {
                kty: "RSA".to_owned(),
                kid: "request-key".to_owned(),
                use_: Some("sig".to_owned()),
                alg: Some("RS256".to_owned()),
                n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
            }],
        };
        let now = chrono::Utc::now().timestamp();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("request-key".to_owned());
        let request_object = jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "iss": "web-client",
                "aud": "https://id.example/default",
                "iat": now,
                "exp": now + 120,
                "jti": "request-object-jti",
                "response_type": "code",
                "client_id": "web-client",
                "redirect_uri": "https://app.example/callback",
                "scope": "openid profile",
                "state": "signed-state",
                "nonce": "signed-nonce",
                "code_challenge": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "code_challenge_method": "S256",
                "claims": {
                    "id_token": {
                        "acr": {
                            "essential": true,
                            "values": [crate::configuration::MFA_ACR]
                        }
                    }
                }
            }),
            &EncodingKey::from_rsa_pem(private_key.as_bytes()).expect("private key"),
        )
        .expect("request object");
        let verified = verify_authorization_request_object(
            &request_object,
            &jwks,
            "web-client",
            "https://id.example/default",
            30,
            now,
        )
        .expect("verified request object");

        assert_eq!(verified.jti, "request-object-jti");
        assert_eq!(verified.request.client_id, "web-client");
        assert_eq!(verified.request.state, "signed-state");
        assert_eq!(
            verified.request.claims.as_deref(),
            Some(
                r#"{"id_token":{"acr":{"essential":true,"values":["urn:robine-id:acr:password+totp"]}}}"#
            )
        );
        assert!(verified.request.request_object.is_none());
        assert!(
            verify_authorization_request_object(
                &request_object,
                &jwks,
                "web-client",
                "https://other-issuer.example",
                30,
                now,
            )
            .is_err()
        );
    }

    #[test]
    fn verifies_an_endpoint_and_token_bound_dpop_proof() {
        let private = SecretKey::random(&mut OsRng);
        let public = private.public_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(public.x().expect("x coordinate"));
        let y = URL_SAFE_NO_PAD.encode(public.y().expect("y coordinate"));
        let jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }))
        .expect("public JWK");
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(jwk);
        let now = chrono::Utc::now().timestamp();
        let access_token = "bound-access-token";
        let proof = jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "jti": "unique-dpop-proof",
                "htm": "GET",
                "htu": "https://id.example/default/userinfo",
                "iat": now,
                "ath": dpop_access_token_hash(access_token),
                "nonce": "server-provided-nonce"
            }),
            &EncodingKey::from_ec_der(private.to_pkcs8_der().expect("private key DER").as_bytes()),
        )
        .expect("DPoP proof");
        let verified = verify_dpop_proof(
            &proof,
            "GET",
            "https://id.example/default/userinfo",
            Some(access_token),
            30,
            now,
        )
        .expect("valid DPoP proof");

        assert_eq!(verified.jti, "unique-dpop-proof");
        assert_eq!(verified.jkt.len(), 43);
        assert_eq!(verified.nonce.as_deref(), Some("server-provided-nonce"));
        assert!(
            verify_dpop_proof(
                &proof,
                "POST",
                "https://id.example/default/userinfo",
                Some(access_token),
                30,
                now,
            )
            .is_err()
        );
        assert!(
            verify_dpop_proof(
                &proof,
                "GET",
                "https://id.example/default/userinfo",
                Some("other-token"),
                30,
                now,
            )
            .is_err()
        );
    }
}
