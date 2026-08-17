use crate::configuration::{Client, Snapshot};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationError {
    pub code: &'static str,
    pub description: &'static str,
}

impl AuthorizationError {
    fn new(code: &'static str, description: &'static str) -> Self {
        Self { code, description }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: String,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub scopes_supported: Vec<String>,
    pub claims_supported: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    #[serde(default)]
    pub nonce: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub ui_locales: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorizationGrant {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub claims: Value,
    pub expires_at: DateTime<Utc>,
}

impl DiscoveryDocument {
    pub fn build(snapshot: &Snapshot, issuer_id: &str) -> Option<Self> {
        let issuer = snapshot.issuer(issuer_id)?;
        let base = issuer.url.trim_end_matches('/').to_owned();

        let mut claims_supported = vec!["sub", "iss", "aud", "iat", "exp", "nonce"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut mapped_claims = snapshot
            .configuration
            .claims
            .keys()
            .filter(|claim| !claims_supported.contains(claim))
            .cloned()
            .collect::<Vec<_>>();
        mapped_claims.sort();
        claims_supported.extend(mapped_claims);

        Some(Self {
            issuer: base.clone(),
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            userinfo_endpoint: format!("{base}/userinfo"),
            jwks_uri: format!("{base}/jwks.json"),
            end_session_endpoint: format!("{base}/logout"),
            response_types_supported: vec!["code"],
            grant_types_supported: vec!["authorization_code"],
            subject_types_supported: vec!["public"],
            id_token_signing_alg_values_supported: vec!["RS256"],
            code_challenge_methods_supported: vec!["S256"],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            scopes_supported: issuer.scopes.clone(),
            claims_supported,
        })
    }
}

impl AuthorizationRequest {
    pub fn validate<'a>(
        &self,
        snapshot: &'a Snapshot,
        issuer_id: &str,
    ) -> Result<&'a Client, AuthorizationError> {
        if snapshot.issuer(issuer_id).is_none() {
            return Err(AuthorizationError::new("invalid_request", "Unknown issuer"));
        }
        if self.response_type != "code" {
            return Err(AuthorizationError::new(
                "unsupported_response_type",
                "Only the authorization code flow is supported",
            ));
        }
        if self.state.is_empty() {
            return Err(AuthorizationError::new(
                "invalid_request",
                "state is required",
            ));
        }
        if !self
            .scope
            .split_ascii_whitespace()
            .any(|scope| scope == "openid")
        {
            return Err(AuthorizationError::new(
                "invalid_scope",
                "The openid scope is required",
            ));
        }

        let client = snapshot
            .client(&self.client_id)
            .ok_or_else(|| AuthorizationError::new("invalid_request", "Unknown client"))?;
        if !client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
        {
            return Err(AuthorizationError::new(
                "unauthorized_client",
                "The client does not allow the authorization code grant",
            ));
        }
        if client.nonce_required.unwrap_or(true) && self.nonce.is_empty() {
            return Err(AuthorizationError::new(
                "invalid_request",
                "nonce is required for this client",
            ));
        }
        if !client.redirect_uris.contains(&self.redirect_uri) {
            return Err(AuthorizationError::new(
                "invalid_request",
                "The redirect URI is not registered for this client",
            ));
        }

        let requested_scopes = self.scope.split_ascii_whitespace().collect::<Vec<_>>();
        if requested_scopes
            .iter()
            .any(|scope| !client.scopes.iter().any(|allowed| allowed == scope))
        {
            return Err(AuthorizationError::new(
                "invalid_scope",
                "One or more requested scopes are not allowed",
            ));
        }

        let pkce_required = client.client_type == "public" || client.pkce_required.unwrap_or(true);
        if pkce_required
            && (self
                .code_challenge
                .as_deref()
                .unwrap_or_default()
                .is_empty()
                || self.code_challenge_method.as_deref() != Some("S256")
                || !self
                    .code_challenge
                    .as_deref()
                    .is_some_and(valid_pkce_challenge))
        {
            return Err(AuthorizationError::new(
                "invalid_request",
                "PKCE using S256 is required for this client",
            ));
        }

        Ok(client)
    }
}

fn valid_pkce_challenge(challenge: &str) -> bool {
    (43..=128).contains(&challenge.len())
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{Branding, Issuer, RootConfiguration};

    fn snapshot() -> Snapshot {
        Snapshot {
            configuration: RootConfiguration {
                schema_version: 1,
                issuers: vec![Issuer {
                    id: "default".to_owned(),
                    url: "https://id.example/default".to_owned(),
                    scopes: vec!["openid".to_owned()],
                    token_policy: crate::configuration::TokenPolicy::default(),
                    branding: None,
                }],
                clients: vec![Client {
                    id: "web".to_owned(),
                    name: "Web".to_owned(),
                    client_type: "public".to_owned(),
                    redirect_uris: vec!["https://app.example/callback".to_owned()],
                    post_logout_redirect_uris: vec![],
                    scopes: vec!["openid".to_owned()],
                    grant_types: vec!["authorization_code".to_owned()],
                    pkce_required: None,
                    nonce_required: None,
                    consent_required: None,
                    authentication_method: None,
                    secret_reference: None,
                    branding: None,
                }],
                branding: Branding::default(),
                users: vec![],
                claims: Default::default(),
                authentication: Default::default(),
            },
            revision: "revision".to_owned(),
        }
    }

    #[test]
    fn rejects_an_unregistered_redirect_uri() {
        let request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://attacker.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
        };

        assert_eq!(
            request
                .validate(&snapshot(), "default")
                .unwrap_err()
                .description,
            "The redirect URI is not registered for this client"
        );
    }

    #[test]
    fn rejects_a_malformed_pkce_challenge() {
        let request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("too-short".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
        };

        assert_eq!(
            request
                .validate(&snapshot(), "default")
                .unwrap_err()
                .description,
            "PKCE using S256 is required for this client"
        );
    }

    #[test]
    fn allows_an_omitted_nonce_only_when_client_policy_allows_it() {
        let mut snapshot = snapshot();
        snapshot.configuration.clients[0].nonce_required = Some(false);
        let request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: String::new(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
        };

        assert!(request.validate(&snapshot, "default").is_ok());
    }

    #[test]
    fn returns_a_standard_error_code_for_an_unsupported_response_type() {
        let request = AuthorizationRequest {
            response_type: "token".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
        };

        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err().code,
            "unsupported_response_type"
        );
    }
}
