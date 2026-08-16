use crate::configuration::{Client, Snapshot};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    pub claims_supported: Vec<&'static str>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
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
            claims_supported: vec!["sub", "iss", "aud", "iat", "exp", "nonce", "name", "email"],
        })
    }
}

impl AuthorizationRequest {
    pub fn validate<'a>(
        &self,
        snapshot: &'a Snapshot,
        issuer_id: &str,
    ) -> Result<&'a Client, &'static str> {
        if snapshot.issuer(issuer_id).is_none() {
            return Err("Unknown issuer");
        }
        if self.response_type != "code" {
            return Err("Only the authorization code flow is supported");
        }
        if self.state.is_empty() || self.nonce.is_empty() {
            return Err("state and nonce are required");
        }
        if !self
            .scope
            .split_ascii_whitespace()
            .any(|scope| scope == "openid")
        {
            return Err("The openid scope is required");
        }

        let client = snapshot.client(&self.client_id).ok_or("Unknown client")?;
        if !client.redirect_uris.contains(&self.redirect_uri) {
            return Err("The redirect URI is not registered for this client");
        }

        let requested_scopes = self.scope.split_ascii_whitespace().collect::<Vec<_>>();
        if requested_scopes
            .iter()
            .any(|scope| !client.scopes.iter().any(|allowed| allowed == scope))
        {
            return Err("One or more requested scopes are not allowed");
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
            return Err("PKCE using S256 is required for this client");
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
                }],
                clients: vec![Client {
                    id: "web".to_owned(),
                    name: "Web".to_owned(),
                    client_type: "public".to_owned(),
                    redirect_uris: vec!["https://app.example/callback".to_owned()],
                    post_logout_redirect_uris: vec![],
                    scopes: vec!["openid".to_owned()],
                    pkce_required: None,
                    nonce_required: None,
                    consent_required: None,
                    authentication_method: None,
                    secret_reference: None,
                }],
                branding: Branding::default(),
                users: vec![],
                claims: Default::default(),
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
        };

        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err(),
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
        };

        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err(),
            "PKCE using S256 is required for this client"
        );
    }
}
