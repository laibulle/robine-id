use crate::configuration::{Client, DEVICE_CODE_GRANT, Snapshot};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const MAX_CLAIMS_PARAMETER_LENGTH: usize = 8_192;
const MAX_AUTHORIZATION_DETAILS_LENGTH: usize = 8_192;
const MAX_AUTHORIZATION_DETAILS: usize = 16;
const MAX_REQUESTED_CLAIMS_PER_DESTINATION: usize = 64;
const MAX_REQUESTED_CLAIM_NAME_LENGTH: usize = 256;
const MAX_REQUESTED_CLAIM_VALUES: usize = 16;
const MAX_REQUESTED_CLAIM_VALUE_LENGTH: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimDestination {
    IdToken,
    UserInfo,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EssentialClaim {
    pub destination: ClaimDestination,
    pub name: String,
    pub accepted_values: Vec<Value>,
}

pub(crate) fn essential_claims_from_parameter(serialized: Option<&str>) -> Vec<EssentialClaim> {
    let Some(claims) = serialized
        .and_then(|claims| serde_json::from_str::<Value>(claims).ok())
        .and_then(|claims| claims.as_object().cloned())
    else {
        return vec![];
    };

    [
        ("id_token", ClaimDestination::IdToken),
        ("userinfo", ClaimDestination::UserInfo),
    ]
    .into_iter()
    .flat_map(|(section, destination)| {
        claims
            .get(section)
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(move |requested| {
                requested.iter().filter_map(move |(name, requirement)| {
                    let requirement = requirement.as_object()?;
                    requirement
                        .get("essential")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                        .then(|| EssentialClaim {
                            destination,
                            name: name.clone(),
                            accepted_values: requested_claim_values(requirement),
                        })
                })
            })
    })
    .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationError {
    pub code: &'static str,
    pub description: &'static str,
}

impl AuthorizationError {
    pub(crate) fn new(code: &'static str, description: &'static str) -> Self {
        Self { code, description }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    pub pushed_authorization_request_endpoint: String,
    pub introspection_endpoint: String,
    pub introspection_signing_alg_values_supported: Vec<&'static str>,
    pub revocation_endpoint: String,
    pub userinfo_endpoint: String,
    pub userinfo_signing_alg_values_supported: Vec<&'static str>,
    pub protected_resources: Vec<String>,
    pub jwks_uri: String,
    pub end_session_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_session_iframe: Option<String>,
    pub frontchannel_logout_supported: bool,
    pub frontchannel_logout_session_supported: bool,
    pub backchannel_logout_supported: bool,
    pub backchannel_logout_session_supported: bool,
    pub response_types_supported: Vec<&'static str>,
    pub response_modes_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub acr_values_supported: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorization_details_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_signing_alg_values_supported: Option<Vec<&'static str>>,
    pub authorization_signing_alg_values_supported: Vec<&'static str>,
    pub dpop_signing_alg_values_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    pub introspection_endpoint_auth_methods_supported: Vec<&'static str>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    pub revocation_endpoint_auth_methods_supported: Vec<&'static str>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    pub service_documentation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<String>,
    pub scopes_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub ui_locales_supported: Vec<String>,
    pub claims_parameter_supported: bool,
    pub request_parameter_supported: bool,
    pub request_object_signing_alg_values_supported: Vec<&'static str>,
    pub request_uri_parameter_supported: bool,
    pub require_pushed_authorization_requests: bool,
    pub authorization_response_iss_parameter_supported: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub jwks_uri: String,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<&'static str>,
    pub resource_signing_alg_values_supported: Vec<&'static str>,
    pub resource_name: String,
    pub resource_documentation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_tos_uri: Option<String>,
    pub dpop_signing_alg_values_supported: Vec<&'static str>,
    pub dpop_bound_access_tokens_required: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizationRequest {
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub nonce: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub ui_locales: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub max_age: Option<String>,
    #[serde(default)]
    pub response_mode: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default, rename = "request")]
    pub request_object: Option<String>,
    #[serde(default)]
    pub request_uri: Option<String>,
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub id_token_hint: Option<String>,
    #[serde(default)]
    pub acr_values: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_claims_parameter")]
    pub claims: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_authorization_details_parameter"
    )]
    pub authorization_details: Option<String>,
    #[serde(default)]
    pub dpop_jkt: Option<String>,
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
    pub response_mode: Option<String>,
    pub resource: Option<String>,
    pub dpop_jkt: Option<String>,
    pub session_id: Option<String>,
    pub auth_time: Option<i64>,
    pub mfa_verified: bool,
    pub claims: Value,
    pub authorization_details: Value,
    pub expires_at: DateTime<Utc>,
}

impl DiscoveryDocument {
    pub fn build(snapshot: &Snapshot, issuer_id: &str) -> Option<Self> {
        let issuer = snapshot.issuer(issuer_id)?;
        let base = issuer.url.trim_end_matches('/').to_owned();
        let branding = snapshot.branding(Some(issuer_id), None);
        let mut documentation_url = url::Url::parse(&base).ok()?;
        documentation_url.set_path("/docs");
        documentation_url.set_query(None);
        documentation_url.set_fragment(None);

        let mut claims_supported = vec![
            "sub",
            "iss",
            "aud",
            "iat",
            "exp",
            "nonce",
            "auth_time",
            "at_hash",
            "acr",
            "amr",
            "sid",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let mut mapped_claims = snapshot
            .configuration
            .claims
            .iter()
            .filter(|(claim, mapping)| {
                issuer.scopes.contains(&mapping.scope) && !claims_supported.contains(claim)
            })
            .map(|(claim, _)| claim.clone())
            .collect::<Vec<_>>();
        mapped_claims.sort();
        claims_supported.extend(mapped_claims);
        let device_authorization_supported =
            snapshot.active_clients_for_issuer(issuer_id).any(|client| {
                client
                    .grant_types
                    .iter()
                    .any(|grant| grant == DEVICE_CODE_GRANT)
                    && client
                        .scopes
                        .iter()
                        .any(|scope| issuer.scopes.contains(scope))
            });

        Some(Self {
            issuer: base.clone(),
            authorization_endpoint: format!("{base}/authorize"),
            token_endpoint: format!("{base}/token"),
            device_authorization_endpoint: device_authorization_supported
                .then(|| format!("{base}/device_authorization")),
            pushed_authorization_request_endpoint: format!("{base}/par"),
            introspection_endpoint: format!("{base}/introspect"),
            introspection_signing_alg_values_supported: vec!["RS256"],
            revocation_endpoint: format!("{base}/revoke"),
            userinfo_endpoint: format!("{base}/userinfo"),
            userinfo_signing_alg_values_supported: vec!["RS256"],
            protected_resources: vec![format!("{base}/userinfo")],
            jwks_uri: format!("{base}/jwks.json"),
            end_session_endpoint: format!("{base}/logout"),
            check_session_iframe: url::Url::parse(&base)
                .is_ok_and(|url| url.scheme() == "https")
                .then(|| format!("{base}/check-session")),
            frontchannel_logout_supported: true,
            frontchannel_logout_session_supported: true,
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
            response_types_supported: vec!["code"],
            response_modes_supported: vec![
                "query",
                "form_post",
                "jwt",
                "query.jwt",
                "form_post.jwt",
            ],
            grant_types_supported: {
                let mut grants = vec!["authorization_code"];
                if issuer.scopes.iter().any(|scope| scope == "offline_access")
                    && snapshot.active_clients_for_issuer(issuer_id).any(|client| {
                        client.scopes.iter().any(|scope| scope == "offline_access")
                            && client
                                .grant_types
                                .iter()
                                .any(|grant| grant == "refresh_token")
                    })
                {
                    grants.push("refresh_token");
                }
                if snapshot.active_clients_for_issuer(issuer_id).any(|client| {
                    client
                        .grant_types
                        .iter()
                        .any(|grant| grant == "client_credentials")
                        && client.scopes.iter().any(|scope| {
                            issuer.scopes.contains(scope)
                                && scope != "openid"
                                && scope != "offline_access"
                                && !snapshot
                                    .configuration
                                    .claims
                                    .values()
                                    .any(|mapping| mapping.scope == *scope)
                        })
                }) {
                    grants.push("client_credentials");
                }
                if snapshot.active_clients_for_issuer(issuer_id).any(|client| {
                    client
                        .grant_types
                        .iter()
                        .any(|grant| grant == "urn:ietf:params:oauth:grant-type:token-exchange")
                        && client
                            .scopes
                            .iter()
                            .any(|scope| issuer.scopes.contains(scope))
                }) {
                    grants.push("urn:ietf:params:oauth:grant-type:token-exchange");
                }
                if device_authorization_supported {
                    grants.push(DEVICE_CODE_GRANT);
                }
                grants
            },
            subject_types_supported: {
                let mut subject_types = vec!["public"];
                if snapshot
                    .active_clients_for_issuer(issuer_id)
                    .any(|client| client.subject_type == "pairwise")
                {
                    subject_types.push("pairwise");
                }
                subject_types
            },
            acr_values_supported: if snapshot
                .configuration
                .authentication
                .methods
                .iter()
                .any(|method| method == "totp")
            {
                vec![crate::tokens::PASSWORD_ACR, crate::tokens::MFA_ACR]
            } else {
                vec![crate::tokens::PASSWORD_ACR]
            },
            authorization_details_types_supported: {
                let mut supported = snapshot
                    .active_clients_for_issuer(issuer_id)
                    .filter(|client| {
                        client
                            .scopes
                            .iter()
                            .any(|scope| issuer.scopes.contains(scope))
                    })
                    .flat_map(|client| client.authorization_details_types.iter().cloned())
                    .collect::<Vec<_>>();
                supported.sort();
                supported.dedup();
                supported
            },
            id_token_signing_alg_values_supported: vec!["RS256"],
            access_token_signing_alg_values_supported: (issuer.token_policy.access_token_format
                == "jwt")
                .then(|| vec!["RS256"]),
            authorization_signing_alg_values_supported: vec!["RS256"],
            dpop_signing_alg_values_supported: vec!["EdDSA", "ES256", "RS256"],
            code_challenge_methods_supported: vec!["S256"],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none",
            ],
            token_endpoint_auth_signing_alg_values_supported: vec![
                "EdDSA", "ES256", "HS256", "RS256",
            ],
            introspection_endpoint_auth_methods_supported: vec![
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
            ],
            introspection_endpoint_auth_signing_alg_values_supported: vec![
                "EdDSA", "ES256", "HS256", "RS256",
            ],
            revocation_endpoint_auth_methods_supported: vec![
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none",
            ],
            revocation_endpoint_auth_signing_alg_values_supported: vec![
                "EdDSA", "ES256", "HS256", "RS256",
            ],
            service_documentation: documentation_url.to_string(),
            op_policy_uri: branding.privacy_url.clone(),
            op_tos_uri: branding.terms_url.clone(),
            scopes_supported: issuer.scopes.clone(),
            claims_supported,
            ui_locales_supported: branding.locales,
            claims_parameter_supported: true,
            request_parameter_supported: true,
            request_object_signing_alg_values_supported: vec!["EdDSA", "ES256", "RS256"],
            // RFC 9126 PAR references remain valid independently of this OIDC
            // Discovery flag. We do not dereference arbitrary Request URIs.
            request_uri_parameter_supported: false,
            require_pushed_authorization_requests: issuer
                .token_policy
                .require_pushed_authorization_requests,
            authorization_response_iss_parameter_supported: true,
        })
    }
}

impl ProtectedResourceMetadata {
    pub fn build(snapshot: &Snapshot, issuer_id: &str) -> Option<Self> {
        let issuer = snapshot.issuer(issuer_id)?;
        let base = issuer.url.trim_end_matches('/').to_owned();
        let branding = snapshot.branding(Some(issuer_id), None);
        let mut documentation_url = url::Url::parse(&base).ok()?;
        documentation_url.set_path("/docs");
        documentation_url.set_query(None);
        documentation_url.set_fragment(None);

        let mut scopes_supported = snapshot
            .configuration
            .claims
            .values()
            .filter(|mapping| issuer.scopes.contains(&mapping.scope))
            .map(|mapping| mapping.scope.clone())
            .collect::<Vec<_>>();
        scopes_supported.sort();
        scopes_supported.dedup();
        if issuer.scopes.iter().any(|scope| scope == "openid") {
            scopes_supported.retain(|scope| scope != "openid");
            scopes_supported.insert(0, "openid".to_owned());
        }

        Some(Self {
            resource: format!("{base}/userinfo"),
            authorization_servers: vec![base.clone()],
            jwks_uri: format!("{base}/jwks.json"),
            scopes_supported,
            bearer_methods_supported: vec!["header"],
            resource_signing_alg_values_supported: vec!["RS256"],
            resource_name: format!("{} UserInfo", branding.product_name),
            resource_documentation: documentation_url.to_string(),
            resource_policy_uri: branding.privacy_url.clone(),
            resource_tos_uri: branding.terms_url.clone(),
            dpop_signing_alg_values_supported: vec!["EdDSA", "ES256", "RS256"],
            dpop_bound_access_tokens_required: false,
        })
    }
}

impl AuthorizationRequest {
    pub fn normalize_empty_optional_parameters(mut self) -> Self {
        for parameter in [
            &mut self.code_challenge,
            &mut self.code_challenge_method,
            &mut self.ui_locales,
            &mut self.prompt,
            &mut self.max_age,
            &mut self.response_mode,
            &mut self.resource,
            &mut self.request_object,
            &mut self.request_uri,
            &mut self.login_hint,
            &mut self.id_token_hint,
            &mut self.acr_values,
            &mut self.claims,
            &mut self.authorization_details,
            &mut self.dpop_jkt,
        ] {
            if parameter.as_deref() == Some("") {
                *parameter = None;
            }
        }
        self
    }

    pub fn validate<'a>(
        &self,
        snapshot: &'a Snapshot,
        issuer_id: &str,
    ) -> Result<&'a Client, AuthorizationError> {
        let issuer = snapshot
            .issuer(issuer_id)
            .ok_or_else(|| AuthorizationError::new("invalid_request", "Unknown issuer"))?;
        if self.response_type.len() > 64
            || self.client_id.is_empty()
            || self.client_id.len() > 256
            || self.redirect_uri.len() > 4_096
            || self.scope.len() > 2_048
            || self.state.len() > 1_024
            || self.nonce.len() > 1_024
            || self
                .ui_locales
                .as_deref()
                .is_some_and(|value| value.len() > 256)
            || self
                .prompt
                .as_deref()
                .is_some_and(|value| value.len() > 128)
            || self
                .max_age
                .as_deref()
                .is_some_and(|value| value.len() > 20)
            || self
                .response_mode
                .as_deref()
                .is_some_and(|value| value.len() > 32)
            || self
                .resource
                .as_deref()
                .is_some_and(|value| value.len() > 4_096)
            || self
                .request_object
                .as_deref()
                .is_some_and(|value| value.len() > 8_192)
            || self
                .request_uri
                .as_deref()
                .is_some_and(|value| value.len() > 4_096)
            || self
                .login_hint
                .as_deref()
                .is_some_and(|value| value.len() > 320)
            || self
                .id_token_hint
                .as_deref()
                .is_some_and(|value| value.len() > 16 * 1024)
            || self
                .acr_values
                .as_deref()
                .is_some_and(|value| value.len() > 2_048)
            || self
                .claims
                .as_deref()
                .is_some_and(|value| value.len() > MAX_CLAIMS_PARAMETER_LENGTH)
        {
            return Err(AuthorizationError::new(
                "invalid_request",
                "One or more authorization parameters exceed the supported length",
            ));
        }
        if self.dpop_jkt.as_deref().is_some_and(|thumbprint| {
            thumbprint.len() != 43
                || !thumbprint
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        }) {
            return Err(AuthorizationError::new(
                "invalid_request",
                "dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint",
            ));
        }
        if self.response_type != "code" {
            return Err(AuthorizationError::new(
                "unsupported_response_type",
                "Only the authorization code flow is supported",
            ));
        }
        if self.response_mode.as_deref().is_some_and(|mode| {
            !matches!(
                mode,
                "query" | "form_post" | "jwt" | "query.jwt" | "form_post.jwt"
            )
        }) {
            return Err(AuthorizationError::new(
                "unsupported_response_mode",
                "Only query, form_post, jwt, query.jwt, and form_post.jwt authorization response modes are supported",
            ));
        }
        if self.request_object.is_some() {
            return Err(AuthorizationError::new(
                "request_not_supported",
                "JWT authorization request objects are not supported",
            ));
        }
        if self.request_uri.is_some() {
            return Err(AuthorizationError::new(
                "request_uri_not_supported",
                "Authorization request URIs are not supported",
            ));
        }
        if self.state.is_empty() {
            return Err(AuthorizationError::new(
                "invalid_request",
                "state is required",
            ));
        }
        self.validate_prompt()?;
        self.validate_claims_parameter(snapshot, issuer_id)?;
        if self.acr_values.as_deref().is_some_and(|acr_values| {
            let values = acr_values.split_ascii_whitespace().collect::<Vec<_>>();
            values.is_empty()
                || values.len() > 16
                || values
                    .iter()
                    .any(|value| value.len() > 256 || value.chars().any(char::is_control))
        }) {
            return Err(AuthorizationError::new(
                "invalid_request",
                "acr_values must contain at most 16 bounded authentication context values",
            ));
        }
        if self.max_age.as_deref().is_some_and(|max_age| {
            max_age.is_empty()
                || !max_age.bytes().all(|byte| byte.is_ascii_digit())
                || max_age.parse::<i64>().is_err()
        }) {
            return Err(AuthorizationError::new(
                "invalid_request",
                "max_age must be a non-negative integer number of seconds",
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
            .client_for_issuer(issuer_id, &self.client_id)
            .ok_or_else(|| AuthorizationError::new("invalid_request", "Unknown client"))?;
        self.authorization_details_value(snapshot, client)?;
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
        if self
            .resource
            .as_ref()
            .is_some_and(|resource| !client.resources.contains(resource))
        {
            return Err(AuthorizationError::new(
                "invalid_target",
                "The requested resource is not registered for this client",
            ));
        }

        let requested_scopes = self.scope.split_ascii_whitespace().collect::<Vec<_>>();
        if requested_scopes.iter().any(|scope| {
            !client.scopes.iter().any(|allowed| allowed == scope)
                || !issuer.scopes.iter().any(|allowed| allowed == scope)
        }) {
            return Err(AuthorizationError::new(
                "invalid_scope",
                "One or more requested scopes are not allowed",
            ));
        }
        if requested_scopes.contains(&"offline_access")
            && !client
                .grant_types
                .iter()
                .any(|grant| grant == "refresh_token")
        {
            return Err(AuthorizationError::new(
                "invalid_scope",
                "offline_access requires the refresh_token grant for this client",
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

    pub fn has_prompt(&self, expected: &str) -> bool {
        self.prompt.as_deref().is_some_and(|prompt| {
            prompt
                .split_ascii_whitespace()
                .any(|value| value == expected)
        })
    }

    pub fn max_age_seconds(&self) -> Option<i64> {
        self.max_age.as_deref()?.parse().ok()
    }

    pub fn requests_scope(&self, expected: &str) -> bool {
        self.scope
            .split_ascii_whitespace()
            .any(|scope| scope == expected)
    }

    pub fn essential_claims(&self) -> Vec<EssentialClaim> {
        essential_claims_from_parameter(self.claims.as_deref())
    }

    pub fn authorization_details_value(
        &self,
        snapshot: &Snapshot,
        client: &Client,
    ) -> Result<Value, AuthorizationError> {
        validated_authorization_details(self.authorization_details.as_deref(), snapshot, client)
    }

    pub fn authentication_context_satisfies(&self, mfa_verified: bool) -> bool {
        let actual = if mfa_verified {
            crate::configuration::MFA_ACR
        } else {
            crate::configuration::PASSWORD_ACR
        };
        self.essential_claims()
            .into_iter()
            .filter(|claim| claim.destination == ClaimDestination::IdToken && claim.name == "acr")
            .all(|claim| {
                claim.accepted_values.is_empty()
                    || claim
                        .accepted_values
                        .iter()
                        .any(|value| value.as_str() == Some(actual))
            })
    }

    fn validate_claims_parameter(
        &self,
        snapshot: &Snapshot,
        issuer_id: &str,
    ) -> Result<(), AuthorizationError> {
        let Some(serialized) = self.claims.as_deref() else {
            return Ok(());
        };
        let claims = serde_json::from_str::<Value>(serialized)
            .ok()
            .and_then(|claims| claims.as_object().cloned())
            .ok_or_else(invalid_claims_parameter)?;
        if claims.is_empty()
            || claims
                .keys()
                .any(|section| !matches!(section.as_str(), "id_token" | "userinfo"))
        {
            return Err(invalid_claims_parameter());
        }
        let requested_scopes = self.scope.split_ascii_whitespace().collect::<Vec<_>>();
        let issuer = snapshot
            .issuer(issuer_id)
            .ok_or_else(|| AuthorizationError::new("invalid_request", "Unknown issuer"))?;
        for (section, destination) in [
            ("id_token", ClaimDestination::IdToken),
            ("userinfo", ClaimDestination::UserInfo),
        ] {
            let Some(requested) = claims.get(section) else {
                continue;
            };
            let requested = requested
                .as_object()
                .filter(|requested| requested.len() <= MAX_REQUESTED_CLAIMS_PER_DESTINATION)
                .ok_or_else(invalid_claims_parameter)?;
            for (name, requirement) in requested {
                if name.is_empty()
                    || name.len() > MAX_REQUESTED_CLAIM_NAME_LENGTH
                    || name.chars().any(char::is_control)
                {
                    return Err(invalid_claims_parameter());
                }
                validate_claim_requirement(requirement)?;
                let essential = requirement
                    .as_object()
                    .and_then(|requirement| requirement.get("essential"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if essential
                    && !essential_claim_available(
                        snapshot,
                        issuer,
                        &requested_scopes,
                        destination,
                        name,
                    )
                {
                    return Err(AuthorizationError::new(
                        "invalid_request",
                        "An essential requested claim is unavailable for the requested scopes",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_prompt(&self) -> Result<(), AuthorizationError> {
        let Some(prompt) = self.prompt.as_deref() else {
            return Ok(());
        };
        let values = prompt.split_ascii_whitespace().collect::<Vec<_>>();
        if values.is_empty()
            || values
                .iter()
                .any(|value| !matches!(*value, "none" | "login" | "consent" | "select_account"))
            || values.iter().enumerate().any(|(index, value)| {
                values
                    .iter()
                    .skip(index + 1)
                    .any(|candidate| candidate == value)
            })
            || (values.contains(&"none") && values.len() != 1)
        {
            return Err(AuthorizationError::new(
                "invalid_request",
                "prompt must contain unique supported values and none cannot be combined",
            ));
        }
        Ok(())
    }
}

fn invalid_claims_parameter() -> AuthorizationError {
    AuthorizationError::new(
        "invalid_request",
        "claims must be a bounded OpenID Connect Claims request object",
    )
}

fn deserialize_optional_claims_parameter<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OptionalClaimsVisitor;
    struct ClaimsVisitor;

    impl<'de> serde::de::Visitor<'de> for OptionalClaimsVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON-serialized Claims parameter or Claims object")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(ClaimsVisitor).map(Some)
        }
    }

    impl<'de> serde::de::Visitor<'de> for ClaimsVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON-serialized Claims parameter or Claims object")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let map = Map::<String, Value>::deserialize(
                serde::de::value::MapAccessDeserializer::new(map),
            )?;
            Ok(Value::Object(map).to_string())
        }
    }

    deserializer.deserialize_option(OptionalClaimsVisitor)
}

fn deserialize_optional_authorization_details_parameter<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OptionalDetailsVisitor;
    struct DetailsVisitor;

    impl<'de> serde::de::Visitor<'de> for OptionalDetailsVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON-serialized authorization details array or JSON array")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(DetailsVisitor).map(Some)
        }
    }

    impl<'de> serde::de::Visitor<'de> for DetailsVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON-serialized authorization details array or JSON array")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_seq<A>(self, sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let values =
                Vec::<Value>::deserialize(serde::de::value::SeqAccessDeserializer::new(sequence))?;
            Ok(Value::Array(values).to_string())
        }
    }

    deserializer.deserialize_option(OptionalDetailsVisitor)
}

pub fn validated_authorization_details(
    serialized: Option<&str>,
    snapshot: &Snapshot,
    client: &Client,
) -> Result<Value, AuthorizationError> {
    let Some(serialized) = serialized else {
        return Ok(Value::Array(vec![]));
    };
    if serialized.len() > MAX_AUTHORIZATION_DETAILS_LENGTH {
        return Err(invalid_authorization_details());
    }
    let details = serde_json::from_str::<Value>(serialized)
        .ok()
        .and_then(|value| value.as_array().cloned())
        .filter(|details| !details.is_empty() && details.len() <= MAX_AUTHORIZATION_DETAILS)
        .ok_or_else(invalid_authorization_details)?;
    let mut nodes = 0usize;
    for detail in &details {
        if !bounded_json(detail, 0, &mut nodes) {
            return Err(invalid_authorization_details());
        }
        let object = detail
            .as_object()
            .filter(|object| !object.is_empty() && object.len() <= 65)
            .ok_or_else(invalid_authorization_details)?;
        let type_id = object
            .get("type")
            .and_then(Value::as_str)
            .filter(|type_id| {
                client
                    .authorization_details_types
                    .iter()
                    .any(|id| id == type_id)
            })
            .ok_or_else(invalid_authorization_details)?;
        let definition = snapshot
            .authorization_detail_type(type_id)
            .ok_or_else(invalid_authorization_details)?;
        if object.keys().any(|field| {
            field != "type"
                && !definition
                    .allowed_fields
                    .iter()
                    .any(|allowed| allowed == field)
        }) || definition
            .required_fields
            .iter()
            .any(|field| !object.contains_key(field))
        {
            return Err(invalid_authorization_details());
        }
        for (field, value) in object {
            match field.as_str() {
                "type" => {}
                "identifier" => {
                    if !bounded_detail_string(value) {
                        return Err(invalid_authorization_details());
                    }
                }
                "locations" => {
                    let Some(locations) = bounded_detail_strings(value) else {
                        return Err(invalid_authorization_details());
                    };
                    if locations.iter().any(|location| {
                        !client.resources.iter().any(|resource| resource == location)
                    }) {
                        return Err(invalid_authorization_details());
                    }
                }
                "actions" | "datatypes" | "privileges"
                    if bounded_detail_strings(value).is_none() =>
                {
                    return Err(invalid_authorization_details());
                }
                _ => {}
            }
        }
    }
    Ok(Value::Array(details))
}

fn invalid_authorization_details() -> AuthorizationError {
    AuthorizationError::new(
        "invalid_authorization_details",
        "authorization_details does not match an allowed registered type",
    )
}

fn bounded_json(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    *nodes = nodes.saturating_add(1);
    if *nodes > 512 || depth > 8 {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(value) => value.len() <= 2_048 && !value.chars().any(char::is_control),
        Value::Array(values) => {
            values.len() <= 64
                && values
                    .iter()
                    .all(|value| bounded_json(value, depth + 1, nodes))
        }
        Value::Object(values) => {
            values.len() <= 64
                && values.iter().all(|(key, value)| {
                    !key.is_empty()
                        && key.len() <= 256
                        && !key.chars().any(char::is_control)
                        && bounded_json(value, depth + 1, nodes)
                })
        }
    }
}

fn bounded_detail_string(value: &Value) -> bool {
    value.as_str().is_some_and(valid_detail_text)
}

fn bounded_detail_strings(value: &Value) -> Option<Vec<&str>> {
    let values = value.as_array()?;
    if values.is_empty() || values.len() > 64 {
        return None;
    }
    values
        .iter()
        .map(|value| value.as_str().filter(|value| valid_detail_text(value)))
        .collect()
}

fn valid_detail_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 2_048 && !value.chars().any(char::is_control)
}

/// Returns true when every requested rich authorization detail is a conservative
/// structural subset of at least one detail in the original grant.
///
/// Authorization detail comparison is type-specific in RFC 9396. Robine ID's
/// configurable detail types therefore use a safe generic rule: scalar values
/// must remain identical, object fields may only be removed, and array members
/// may only be removed. This permits downscoping without granting new values.
pub fn authorization_details_subset(requested: &Value, granted: &Value) -> bool {
    let (Some(requested), Some(granted)) = (requested.as_array(), granted.as_array()) else {
        return false;
    };
    !requested.is_empty()
        && requested.iter().all(|requested_detail| {
            granted.iter().any(|granted_detail| {
                requested_detail
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some()
                    && requested_detail.get("type") == granted_detail.get("type")
                    && authorization_detail_value_subset(requested_detail, granted_detail)
            })
        })
}

fn authorization_detail_value_subset(requested: &Value, granted: &Value) -> bool {
    match (requested, granted) {
        (Value::Object(requested), Value::Object(granted)) => {
            requested.iter().all(|(key, value)| {
                granted
                    .get(key)
                    .is_some_and(|granted| authorization_detail_value_subset(value, granted))
            })
        }
        (Value::Array(requested), Value::Array(granted)) => requested.iter().all(|value| {
            granted
                .iter()
                .any(|granted| authorization_detail_value_subset(value, granted))
        }),
        _ => requested == granted,
    }
}

fn validate_claim_requirement(requirement: &Value) -> Result<(), AuthorizationError> {
    if requirement.is_null() {
        return Ok(());
    }
    let requirement = requirement
        .as_object()
        .filter(|requirement| {
            requirement
                .keys()
                .all(|key| matches!(key.as_str(), "essential" | "value" | "values"))
        })
        .ok_or_else(invalid_claims_parameter)?;
    if requirement
        .get("essential")
        .is_some_and(|essential| !essential.is_boolean())
        || (requirement.contains_key("value") && requirement.contains_key("values"))
    {
        return Err(invalid_claims_parameter());
    }
    if let Some(value) = requirement.get("value") {
        validate_requested_claim_value(value)?;
    }
    if let Some(values) = requirement.get("values") {
        let values = values
            .as_array()
            .filter(|values| !values.is_empty() && values.len() <= MAX_REQUESTED_CLAIM_VALUES)
            .ok_or_else(invalid_claims_parameter)?;
        for value in values {
            validate_requested_claim_value(value)?;
        }
    }
    Ok(())
}

fn validate_requested_claim_value(value: &Value) -> Result<(), AuthorizationError> {
    let valid = match value {
        Value::String(value) => {
            value.len() <= MAX_REQUESTED_CLAIM_VALUE_LENGTH && !value.chars().any(char::is_control)
        }
        Value::Bool(_) | Value::Number(_) => true,
        Value::Null | Value::Array(_) | Value::Object(_) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_claims_parameter())
    }
}

fn requested_claim_values(requirement: &Map<String, Value>) -> Vec<Value> {
    requirement
        .get("value")
        .cloned()
        .into_iter()
        .chain(
            requirement
                .get("values")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .cloned(),
        )
        .collect()
}

fn essential_claim_available(
    snapshot: &Snapshot,
    issuer: &crate::configuration::Issuer,
    requested_scopes: &[&str],
    destination: ClaimDestination,
    name: &str,
) -> bool {
    let built_in = match destination {
        ClaimDestination::IdToken => matches!(
            name,
            "sub"
                | "iss"
                | "aud"
                | "iat"
                | "exp"
                | "nonce"
                | "auth_time"
                | "at_hash"
                | "acr"
                | "amr"
        ),
        ClaimDestination::UserInfo => name == "sub",
    };
    built_in
        || snapshot
            .configuration
            .claims
            .get(name)
            .is_some_and(|mapping| {
                issuer.scopes.contains(&mapping.scope)
                    && requested_scopes.contains(&mapping.scope.as_str())
            })
}

pub(crate) fn valid_pkce_challenge(challenge: &str) -> bool {
    (43..=128).contains(&challenge.len())
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{AuthorizationDetailType, Branding, Issuer, RootConfiguration};
    use serde_json::json;

    fn snapshot() -> Snapshot {
        Snapshot {
            configuration: RootConfiguration {
                schema_version: 1,
                pairwise_subject_salt_reference: None,
                issuers: vec![Issuer {
                    enabled: true,
                    id: "default".to_owned(),
                    url: "https://id.example/default".to_owned(),
                    scopes: vec!["openid".to_owned()],
                    token_policy: crate::configuration::TokenPolicy::default(),
                    branding: None,
                }],
                clients: vec![Client {
                    enabled: true,
                    issuer_ids: vec![],
                    id: "web".to_owned(),
                    name: "Web".to_owned(),
                    client_type: "public".to_owned(),
                    subject_type: "public".to_owned(),
                    sector_identifier: None,
                    redirect_uris: vec!["https://app.example/callback".to_owned()],
                    post_logout_redirect_uris: vec![],
                    frontchannel_logout_uri: None,
                    frontchannel_logout_session_required: false,
                    backchannel_logout_uri: None,
                    backchannel_logout_session_required: false,
                    resources: vec![],
                    scopes: vec!["openid".to_owned()],
                    grant_types: vec!["authorization_code".to_owned()],
                    pkce_required: None,
                    nonce_required: None,
                    consent_required: None,
                    introspection_allowed: false,
                    userinfo_signed_response_alg: None,
                    require_pushed_authorization_requests: false,
                    require_signed_request_object: false,
                    request_object_jwks: None,
                    required_acr: None,
                    max_authentication_age: None,
                    actor_token_exchange_allowed: false,
                    authorized_actor_clients: vec![],
                    authorization_details_types: vec![],
                    authentication_method: None,
                    secret_reference: None,
                    jwks: None,
                    branding: None,
                }],
                branding: Branding::default(),
                users: vec![],
                claims: Default::default(),
                authorization_detail_types: vec![],
                authentication: Default::default(),
                reconciliation: Default::default(),
                storage: None,
                telemetry: Default::default(),
            },
            revision: "revision".to_owned(),
        }
    }

    #[test]
    fn metadata_builders_fail_closed_for_an_internally_malformed_issuer_url() {
        let mut malformed = snapshot();
        malformed.configuration.issuers[0].url = "not an issuer URL".to_owned();

        assert!(DiscoveryDocument::build(&malformed, "default").is_none());
        assert!(ProtectedResourceMetadata::build(&malformed, "default").is_none());
    }

    #[test]
    fn discovery_advertises_only_configured_subject_types() {
        let public = snapshot();
        assert_eq!(
            DiscoveryDocument::build(&public, "default")
                .expect("discovery")
                .subject_types_supported,
            vec!["public"]
        );

        let mut pairwise = snapshot();
        pairwise.configuration.clients[0].subject_type = "pairwise".to_owned();
        pairwise.configuration.pairwise_subject_salt_reference = Some(json!({
            "provider": "env",
            "key": "PAIRWISE_SUBJECT_SALT"
        }));
        assert_eq!(
            DiscoveryDocument::build(&pairwise, "default")
                .expect("pairwise discovery")
                .subject_types_supported,
            vec!["public", "pairwise"]
        );
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
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
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
    fn accepts_only_resources_registered_by_the_client() {
        let mut snapshot = snapshot();
        snapshot.configuration.clients[0].resources =
            vec!["https://api.example/resource".to_owned()];
        let mut request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: Some("https://api.example/resource".to_owned()),
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };
        assert!(request.validate(&snapshot, "default").is_ok());
        request.resource = Some("https://other-api.example/resource".to_owned());
        assert_eq!(
            request.validate(&snapshot, "default").unwrap_err().code,
            "invalid_target"
        );
    }

    #[test]
    fn rejects_authorization_for_a_client_bound_to_another_issuer() {
        let mut snapshot = snapshot();
        let mut other = snapshot.configuration.issuers[0].clone();
        other.id = "other".to_owned();
        other.url = "https://id.example/other".to_owned();
        snapshot.configuration.issuers.push(other);
        snapshot.configuration.clients[0].issuer_ids = vec!["default".to_owned()];
        let request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };

        assert!(request.validate(&snapshot, "default").is_ok());
        let error = request
            .validate(&snapshot, "other")
            .expect_err("client must not cross issuers");
        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.description, "Unknown client");
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
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
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
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
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
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };

        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err().code,
            "unsupported_response_type"
        );
    }

    #[test]
    fn rejects_client_scopes_not_supported_by_the_selected_issuer() {
        let mut snapshot = snapshot();
        snapshot.configuration.clients[0]
            .scopes
            .push("profile".to_owned());
        let request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid profile".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };

        assert_eq!(
            request.validate(&snapshot, "default").unwrap_err().code,
            "invalid_scope"
        );
    }

    #[test]
    fn advertises_and_authorizes_offline_access_only_for_refresh_clients() {
        let mut snapshot = snapshot();
        snapshot.configuration.issuers[0]
            .scopes
            .push("offline_access".to_owned());
        snapshot.configuration.clients[0]
            .scopes
            .push("offline_access".to_owned());
        let request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid offline_access".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
            prompt: Some("consent".to_owned()),
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };

        assert_eq!(
            request.validate(&snapshot, "default").unwrap_err().code,
            "invalid_scope"
        );
        snapshot.configuration.clients[0]
            .grant_types
            .push("refresh_token".to_owned());
        assert!(request.validate(&snapshot, "default").is_ok());
        assert!(request.requests_scope("offline_access"));
        assert!(
            DiscoveryDocument::build(&snapshot, "default")
                .expect("discovery")
                .grant_types_supported
                .contains(&"refresh_token")
        );
    }

    #[test]
    fn advertises_explicit_supported_and_unsupported_request_capabilities() {
        let discovery = DiscoveryDocument::build(&snapshot(), "default").expect("discovery");

        assert_eq!(
            discovery.response_modes_supported,
            vec!["query", "form_post", "jwt", "query.jwt", "form_post.jwt"]
        );
        assert_eq!(
            discovery.authorization_signing_alg_values_supported,
            vec!["RS256"]
        );
        assert_eq!(
            discovery.userinfo_signing_alg_values_supported,
            vec!["RS256"]
        );
        assert_eq!(
            discovery.protected_resources,
            vec!["https://id.example/default/userinfo"]
        );
        assert_eq!(discovery.access_token_signing_alg_values_supported, None);
        assert_eq!(
            discovery.dpop_signing_alg_values_supported,
            vec!["EdDSA", "ES256", "RS256"]
        );
        assert!(discovery.authorization_response_iss_parameter_supported);
        assert_eq!(
            discovery.check_session_iframe.as_deref(),
            Some("https://id.example/default/check-session")
        );
        let mut plain_http = snapshot();
        plain_http.configuration.issuers[0].url = "http://127.0.0.1:4001/default".to_owned();
        assert_eq!(
            DiscoveryDocument::build(&plain_http, "default")
                .expect("loopback discovery")
                .check_session_iframe,
            None
        );
        assert!(discovery.claims_parameter_supported);
        assert!(discovery.request_parameter_supported);
        assert_eq!(
            discovery.request_object_signing_alg_values_supported,
            vec!["EdDSA", "ES256", "RS256"]
        );
        assert!(!discovery.request_uri_parameter_supported);
        assert!(!discovery.require_pushed_authorization_requests);
        assert_eq!(
            discovery.pushed_authorization_request_endpoint,
            "https://id.example/default/par"
        );
        assert_eq!(discovery.ui_locales_supported, vec!["en", "fr"]);
        assert_eq!(
            discovery.token_endpoint_auth_methods_supported,
            vec![
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ]
        );
        assert_eq!(
            discovery.token_endpoint_auth_signing_alg_values_supported,
            vec!["EdDSA", "ES256", "HS256", "RS256"]
        );
        assert_eq!(
            discovery.introspection_endpoint_auth_methods_supported,
            vec![
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt"
            ]
        );
        assert_eq!(
            discovery.introspection_signing_alg_values_supported,
            vec!["RS256"]
        );
        assert_eq!(
            discovery.introspection_endpoint_auth_signing_alg_values_supported,
            vec!["EdDSA", "ES256", "HS256", "RS256"]
        );
        assert_eq!(
            discovery.revocation_endpoint_auth_methods_supported,
            vec![
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ]
        );
        assert_eq!(
            discovery.revocation_endpoint_auth_signing_alg_values_supported,
            vec!["EdDSA", "ES256", "HS256", "RS256"]
        );
        assert_eq!(discovery.service_documentation, "https://id.example/docs");
        assert_eq!(discovery.op_policy_uri, None);
        assert_eq!(discovery.op_tos_uri, None);

        let mut branded_snapshot = snapshot();
        branded_snapshot.configuration.branding.privacy_url =
            Some("https://id.example/privacy".to_owned());
        branded_snapshot.configuration.branding.terms_url =
            Some("https://id.example/terms".to_owned());
        let branded =
            DiscoveryDocument::build(&branded_snapshot, "default").expect("branded discovery");
        assert_eq!(
            branded.op_policy_uri.as_deref(),
            Some("https://id.example/privacy")
        );
        assert_eq!(
            branded.op_tos_uri.as_deref(),
            Some("https://id.example/terms")
        );

        let mut jwt_snapshot = snapshot();
        jwt_snapshot.configuration.issuers[0]
            .token_policy
            .access_token_format = "jwt".to_owned();
        assert_eq!(
            DiscoveryDocument::build(&jwt_snapshot, "default")
                .expect("JWT discovery")
                .access_token_signing_alg_values_supported,
            Some(vec!["RS256"])
        );
        assert!(discovery.claims_supported.contains(&"auth_time".to_owned()));
        assert!(discovery.claims_supported.contains(&"at_hash".to_owned()));
        assert!(discovery.claims_supported.contains(&"acr".to_owned()));
        assert!(discovery.claims_supported.contains(&"amr".to_owned()));
        assert!(discovery.claims_supported.contains(&"sid".to_owned()));
        assert!(discovery.backchannel_logout_supported);
        assert!(discovery.backchannel_logout_session_supported);
        assert!(discovery.frontchannel_logout_supported);
        assert!(discovery.frontchannel_logout_session_supported);
        assert_eq!(
            discovery.acr_values_supported,
            vec![crate::tokens::PASSWORD_ACR]
        );
        let mut mfa_snapshot = snapshot();
        mfa_snapshot
            .configuration
            .authentication
            .methods
            .push("totp".to_owned());
        assert_eq!(
            DiscoveryDocument::build(&mfa_snapshot, "default")
                .expect("MFA discovery")
                .acr_values_supported,
            vec![crate::tokens::PASSWORD_ACR, crate::tokens::MFA_ACR]
        );
    }

    #[test]
    fn publishes_exact_user_info_protected_resource_metadata() {
        let metadata =
            ProtectedResourceMetadata::build(&snapshot(), "default").expect("resource metadata");

        assert_eq!(metadata.resource, "https://id.example/default/userinfo");
        assert_eq!(
            metadata.authorization_servers,
            vec!["https://id.example/default"]
        );
        assert_eq!(metadata.jwks_uri, "https://id.example/default/jwks.json");
        assert_eq!(metadata.scopes_supported, vec!["openid"]);
        assert_eq!(metadata.bearer_methods_supported, vec!["header"]);
        assert_eq!(
            metadata.resource_signing_alg_values_supported,
            vec!["RS256"]
        );
        assert_eq!(
            metadata.dpop_signing_alg_values_supported,
            vec!["EdDSA", "ES256", "RS256"]
        );
        assert!(!metadata.dpop_bound_access_tokens_required);

        let mut scoped_snapshot = snapshot();
        scoped_snapshot.configuration.issuers[0].scopes.extend([
            "profile".to_owned(),
            "offline_access".to_owned(),
            "service.read".to_owned(),
        ]);
        scoped_snapshot.configuration.claims.insert(
            "name".to_owned(),
            crate::configuration::ClaimMapping {
                source: "name".to_owned(),
                scope: "profile".to_owned(),
            },
        );
        let scoped = ProtectedResourceMetadata::build(&scoped_snapshot, "default")
            .expect("scoped resource metadata");
        assert_eq!(scoped.scopes_supported, vec!["openid", "profile"]);
        assert!(ProtectedResourceMetadata::build(&snapshot(), "missing").is_none());
    }

    #[test]
    fn advertises_client_credentials_only_when_configured() {
        let mut snapshot = snapshot();
        assert!(
            !DiscoveryDocument::build(&snapshot, "default")
                .expect("discovery")
                .grant_types_supported
                .contains(&"client_credentials")
        );
        let mut service = snapshot.configuration.clients[0].clone();
        service.id = "service".to_owned();
        service.client_type = "confidential".to_owned();
        service.redirect_uris.clear();
        service.scopes = vec!["service.read".to_owned()];
        service.grant_types = vec!["client_credentials".to_owned()];
        service.authentication_method = Some("client_secret_basic".to_owned());
        service.secret_reference = Some(serde_json::json!({
            "provider": "env",
            "key": "SERVICE_CLIENT_SECRET"
        }));
        snapshot.configuration.issuers[0]
            .scopes
            .push("service.read".to_owned());
        snapshot.configuration.clients.push(service);

        assert!(
            DiscoveryDocument::build(&snapshot, "default")
                .expect("discovery")
                .grant_types_supported
                .contains(&"client_credentials")
        );
        snapshot.configuration.issuers[0]
            .scopes
            .retain(|scope| scope != "service.read");
        assert!(
            !DiscoveryDocument::build(&snapshot, "default")
                .expect("discovery")
                .grant_types_supported
                .contains(&"client_credentials")
        );
    }

    #[test]
    fn advertises_device_authorization_only_when_configured() {
        let mut snapshot = snapshot();
        let discovery = DiscoveryDocument::build(&snapshot, "default").expect("discovery");
        assert_eq!(discovery.device_authorization_endpoint, None);
        assert!(!discovery.grant_types_supported.contains(&DEVICE_CODE_GRANT));

        snapshot.configuration.clients[0]
            .grant_types
            .push(DEVICE_CODE_GRANT.to_owned());
        let discovery = DiscoveryDocument::build(&snapshot, "default").expect("device discovery");
        assert_eq!(
            discovery.device_authorization_endpoint.as_deref(),
            Some("https://id.example/default/device_authorization")
        );
        assert!(discovery.grant_types_supported.contains(&DEVICE_CODE_GRANT));

        snapshot.configuration.issuers[0].scopes.clear();
        let discovery =
            DiscoveryDocument::build(&snapshot, "default").expect("unsupported issuer discovery");
        assert_eq!(discovery.device_authorization_endpoint, None);
        assert!(!discovery.grant_types_supported.contains(&DEVICE_CODE_GRANT));
    }

    #[test]
    fn disabled_clients_do_not_contribute_dynamic_discovery_capabilities() {
        let mut snapshot = snapshot();
        snapshot.configuration.issuers[0]
            .scopes
            .extend(["offline_access".to_owned(), "service.read".to_owned()]);
        let client = snapshot
            .configuration
            .clients
            .first_mut()
            .expect("configured client");
        client.enabled = false;
        client.subject_type = "pairwise".to_owned();
        client
            .scopes
            .extend(["offline_access".to_owned(), "service.read".to_owned()]);
        client.grant_types.extend([
            "refresh_token".to_owned(),
            "client_credentials".to_owned(),
            "urn:ietf:params:oauth:grant-type:token-exchange".to_owned(),
            DEVICE_CODE_GRANT.to_owned(),
        ]);
        client
            .authorization_details_types
            .push("account_information".to_owned());

        let discovery = DiscoveryDocument::build(&snapshot, "default").expect("discovery");
        assert_eq!(discovery.device_authorization_endpoint, None);
        assert_eq!(discovery.grant_types_supported, vec!["authorization_code"]);
        assert_eq!(discovery.subject_types_supported, vec!["public"]);
        assert!(discovery.authorization_details_types_supported.is_empty());
    }

    #[test]
    fn advertises_token_exchange_only_when_configured() {
        let mut snapshot = snapshot();
        let grant = "urn:ietf:params:oauth:grant-type:token-exchange";
        assert!(
            !DiscoveryDocument::build(&snapshot, "default")
                .expect("discovery")
                .grant_types_supported
                .contains(&grant)
        );

        snapshot.configuration.clients[0]
            .grant_types
            .push(grant.to_owned());
        snapshot.configuration.clients[0]
            .resources
            .push("https://api.example/resource".to_owned());
        assert!(
            DiscoveryDocument::build(&snapshot, "default")
                .expect("discovery")
                .grant_types_supported
                .contains(&grant)
        );
    }

    #[test]
    fn rejects_unadvertised_response_modes_and_request_objects() {
        let mut request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
            prompt: None,
            max_age: None,
            response_mode: Some("query".to_owned()),
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };

        assert!(request.validate(&snapshot(), "default").is_ok());
        request.response_mode = Some("fragment".to_owned());
        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err().code,
            "unsupported_response_mode"
        );
        request.response_mode = Some("query".to_owned());
        request.request_object = Some("header.payload.signature".to_owned());
        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err().code,
            "request_not_supported"
        );
        request.request_object = None;
        request.response_mode = Some("form_post".to_owned());
        assert!(request.validate(&snapshot(), "default").is_ok());
        request.response_mode = Some("query.jwt".to_owned());
        assert!(request.validate(&snapshot(), "default").is_ok());
        request.response_mode = Some("jwt".to_owned());
        assert!(request.validate(&snapshot(), "default").is_ok());
        request.response_mode = Some("form_post.jwt".to_owned());
        assert!(request.validate(&snapshot(), "default").is_ok());
        request.request_uri = Some("https://client.example/request.jwt".to_owned());
        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err().code,
            "request_uri_not_supported"
        );
        request.request_uri = None;
        request.login_hint = Some("x".repeat(321));
        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err().code,
            "invalid_request"
        );
        request.login_hint = None;
        request.id_token_hint = Some("x".repeat(16 * 1024 + 1));
        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err().code,
            "invalid_request"
        );
        request.id_token_hint = None;
        request.dpop_jkt = Some("short".to_owned());
        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err().code,
            "invalid_request"
        );
        request.dpop_jkt = Some("A".repeat(43));
        assert!(request.validate(&snapshot(), "default").is_ok());
    }

    #[test]
    fn treats_empty_optional_authorization_parameters_as_omitted() {
        let request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: Some(String::new()),
            prompt: Some(String::new()),
            max_age: Some(String::new()),
            response_mode: Some(String::new()),
            resource: Some(String::new()),
            request_object: Some(String::new()),
            request_uri: Some(String::new()),
            login_hint: Some(String::new()),
            id_token_hint: Some(String::new()),
            acr_values: Some(String::new()),
            claims: Some(String::new()),
            authorization_details: None,
            dpop_jkt: Some(String::new()),
        }
        .normalize_empty_optional_parameters();

        assert!(request.validate(&snapshot(), "default").is_ok());
        assert!(request.response_mode.is_none());
        assert!(request.request_object.is_none());
        assert!(request.request_uri.is_none());
        assert!(request.id_token_hint.is_none());
    }

    #[test]
    fn validates_supported_prompt_combinations() {
        let mut request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
            prompt: Some("login consent".to_owned()),
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };
        assert!(request.validate(&snapshot(), "default").is_ok());
        assert!(request.has_prompt("login"));

        for invalid in ["none login", "unknown", "login login", ""] {
            request.prompt = Some(invalid.to_owned());
            assert_eq!(
                request.validate(&snapshot(), "default").unwrap_err().code,
                "invalid_request"
            );
        }

        request.prompt = None;
        request.max_age = Some("0".to_owned());
        assert_eq!(request.max_age_seconds(), Some(0));
        assert!(request.validate(&snapshot(), "default").is_ok());
        for invalid in ["-1", "+1", "1.5", "forever"] {
            request.max_age = Some(invalid.to_owned());
            assert_eq!(
                request.validate(&snapshot(), "default").unwrap_err().code,
                "invalid_request"
            );
        }

        request.max_age = None;
        request.acr_values = Some(format!(
            "{} {} urn:example:unknown",
            crate::configuration::MFA_ACR,
            crate::configuration::PASSWORD_ACR
        ));
        assert!(request.validate(&snapshot(), "default").is_ok());
        for invalid in [
            " ".to_owned(),
            std::iter::repeat_n("urn:example:acr", 17)
                .collect::<Vec<_>>()
                .join(" "),
            format!("urn:example:{}", "x".repeat(257)),
        ] {
            request.acr_values = Some(invalid);
            assert_eq!(
                request.validate(&snapshot(), "default").unwrap_err().code,
                "invalid_request"
            );
        }
        request.acr_values = None;
        request.claims = Some(
            serde_json::json!({
                "id_token": {
                    "acr": {
                        "essential": true,
                        "values": [crate::configuration::MFA_ACR]
                    },
                    "auth_time": {"essential": true}
                },
                "userinfo": {"sub": null}
            })
            .to_string(),
        );
        assert!(request.validate(&snapshot(), "default").is_ok());
        assert!(!request.authentication_context_satisfies(false));
        assert!(request.authentication_context_satisfies(true));
        assert_eq!(request.essential_claims().len(), 2);

        for invalid in [
            "not-json".to_owned(),
            "x".repeat(MAX_CLAIMS_PARAMETER_LENGTH + 1),
            serde_json::json!({"unsupported": {}}).to_string(),
            serde_json::json!({"id_token": {"acr": {"essential": "yes"}}}).to_string(),
            serde_json::json!({"id_token": {"acr": {"value": "a", "values": ["b"]}}}).to_string(),
            serde_json::json!({"id_token": {"acr": {"values": []}}}).to_string(),
            serde_json::json!({
                "id_token": {
                    "acr": {
                        "values": std::iter::repeat_n("urn:example:acr", 17).collect::<Vec<_>>()
                    }
                }
            })
            .to_string(),
            Value::Object(Map::from_iter([(
                "id_token".to_owned(),
                Value::Object(Map::from_iter(
                    (0..65).map(|index| (format!("claim-{index}"), Value::Null)),
                )),
            )]))
            .to_string(),
        ] {
            request.claims = Some(invalid);
            assert_eq!(
                request.validate(&snapshot(), "default").unwrap_err().code,
                "invalid_request"
            );
        }

        request.claims =
            Some(serde_json::json!({"userinfo": {"department": {"essential": true}}}).to_string());
        assert_eq!(
            request
                .validate(&snapshot(), "default")
                .unwrap_err()
                .description,
            "An essential requested claim is unavailable for the requested scopes"
        );

        request.claims = None;
        request.state = "s".repeat(1_025);
        assert_eq!(
            request.validate(&snapshot(), "default").unwrap_err().code,
            "invalid_request"
        );
    }

    #[test]
    fn discovery_lists_only_claims_reachable_through_issuer_scopes() {
        let mut snapshot = snapshot();
        snapshot.configuration.claims.insert(
            "department".to_owned(),
            crate::configuration::ClaimMapping {
                source: "department".to_owned(),
                scope: "organization".to_owned(),
            },
        );
        let discovery = DiscoveryDocument::build(&snapshot, "default").expect("discovery");

        assert!(
            !discovery
                .claims_supported
                .contains(&"department".to_owned())
        );
    }

    #[test]
    fn validates_registered_rich_authorization_details() {
        let mut snapshot = snapshot();
        snapshot
            .configuration
            .authorization_detail_types
            .push(AuthorizationDetailType {
                type_id: "account_information".to_owned(),
                name: "Account information".to_owned(),
                allowed_fields: vec![
                    "actions".to_owned(),
                    "identifier".to_owned(),
                    "locations".to_owned(),
                ],
                required_fields: vec!["actions".to_owned()],
            });
        let client = snapshot.configuration.clients.first_mut().expect("client");
        client.authorization_details_types = vec!["account_information".to_owned()];
        client.resources = vec!["https://api.example/accounts".to_owned()];
        let client = snapshot.client("web").expect("client");

        let details = json!([{
            "type": "account_information",
            "actions": ["read_balances", "read_transactions"],
            "identifier": "account-42",
            "locations": ["https://api.example/accounts"]
        }]);
        assert_eq!(
            validated_authorization_details(Some(&details.to_string()), &snapshot, client)
                .expect("valid details"),
            details
        );
        assert_eq!(
            DiscoveryDocument::build(&snapshot, "default")
                .expect("discovery")
                .authorization_details_types_supported,
            ["account_information"]
        );

        for invalid in [
            json!([]),
            json!([{"actions": ["read_balances"]}]),
            json!([{"type": "unknown", "actions": ["read_balances"]}]),
            json!([{"type": "account_information"}]),
            json!([{"type": "account_information", "actions": ["read_balances"], "unknown": true}]),
            json!([{"type": "account_information", "actions": [], "locations": ["https://evil.example"]}]),
        ] {
            assert_eq!(
                validated_authorization_details(Some(&invalid.to_string()), &snapshot, client)
                    .unwrap_err()
                    .code,
                "invalid_authorization_details"
            );
        }
        let oversized = format!(
            r#"[{{"type":"account_information","actions":["read_balances"],"identifier":"{}"}}]"#,
            "x".repeat(MAX_AUTHORIZATION_DETAILS_LENGTH)
        );
        assert_eq!(
            validated_authorization_details(Some(&oversized), &snapshot, client)
                .unwrap_err()
                .code,
            "invalid_authorization_details"
        );
    }

    #[test]
    fn rich_authorization_details_can_only_be_downscoped() {
        let granted = json!([{
            "type": "account_information",
            "actions": ["read_balances", "read_transactions"],
            "identifier": "account-42"
        }]);
        assert!(authorization_details_subset(
            &json!([{
                "type": "account_information",
                "actions": ["read_balances"]
            }]),
            &granted
        ));
        assert!(!authorization_details_subset(
            &json!([{
                "type": "account_information",
                "actions": ["initiate_payment"]
            }]),
            &granted
        ));
        assert!(!authorization_details_subset(
            &json!([{
                "type": "payment_initiation",
                "actions": ["read_balances"]
            }]),
            &granted
        ));
        assert!(!authorization_details_subset(&json!([]), &granted));
    }
}
