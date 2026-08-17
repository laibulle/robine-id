use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};
use thiserror::Error;

const EMBEDDED_ROOT: &str = include_str!("../config/robine_id.json");
const MAX_RESOURCES: usize = 10_000;
const MAX_IDENTIFIER_LENGTH: usize = 256;
const MAX_URL_LENGTH: usize = 4_096;
const MAX_DISPLAY_TEXT_LENGTH: usize = 2_048;
pub const SIGNING_KEY_RETENTION_SAFETY_SECONDS: i64 = 300;
pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const PASSWORD_ACR: &str = "urn:robine-id:acr:password";
pub const MFA_ACR: &str = "urn:robine-id:acr:password+totp";
const FALLBACK_DUMMY_PASSWORD_HASH: &str =
    "$2b$12$.JtidA6ZMWny4XaLMozDSOupYHbVNQurj8NkCdM9D3m/g3v3fyXXa";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfiguration {
    pub schema_version: u8,
    pub issuers: Vec<Issuer>,
    #[serde(default)]
    pub clients: Vec<Client>,
    #[serde(default)]
    pub branding: Branding,
    #[serde(default)]
    pub users: Vec<User>,
    #[serde(default)]
    pub claims: std::collections::HashMap<String, ClaimMapping>,
    #[serde(default)]
    pub authentication: AuthenticationPolicy,
    #[serde(default)]
    pub reconciliation: ReconciliationPolicy,
    #[serde(default)]
    pub storage: Option<StorageConfiguration>,
    #[serde(default)]
    pub telemetry: TelemetryConfiguration,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    pub id: String,
    pub url: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub token_policy: TokenPolicy,
    #[serde(default)]
    pub branding: Option<BrandingOverride>,
}

impl Issuer {
    pub fn signing_key_retention_seconds(&self) -> i64 {
        let signed_token_lifetime = if self.token_policy.access_token_format == "jwt" {
            self.token_policy
                .id_token_lifetime
                .max(self.token_policy.access_token_lifetime)
        } else {
            self.token_policy.id_token_lifetime
        };
        signed_token_lifetime
            .saturating_add(self.token_policy.clock_skew)
            .saturating_add(SIGNING_KEY_RETENTION_SAFETY_SECONDS)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default = "default_client_type")]
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub pkce_required: Option<bool>,
    #[serde(default)]
    pub nonce_required: Option<bool>,
    #[serde(default)]
    pub consent_required: Option<bool>,
    #[serde(default)]
    pub introspection_allowed: bool,
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    #[serde(default)]
    pub required_acr: Option<String>,
    pub authentication_method: Option<String>,
    pub secret_reference: Option<serde_json::Value>,
    #[serde(default)]
    pub jwks: Option<ClientJwkSet>,
    #[serde(default)]
    pub branding: Option<BrandingOverride>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientJwkSet {
    pub keys: Vec<ClientJwk>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientJwk {
    pub kty: String,
    pub kid: String,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    pub n: String,
    pub e: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub id: String,
    pub identifier: String,
    pub password_hash: String,
    #[serde(default)]
    pub totp_secret_reference: Option<serde_json::Value>,
    pub name: Option<String>,
    pub email: Option<String>,
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimMapping {
    pub source: String,
    pub scope: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenPolicy {
    #[serde(default = "default_authorization_code_lifetime")]
    pub authorization_code_lifetime: i64,
    #[serde(default = "default_browser_authorization_lifetime")]
    pub browser_authorization_lifetime: i64,
    #[serde(default = "default_pushed_authorization_request_lifetime")]
    pub pushed_authorization_request_lifetime: i64,
    #[serde(default = "default_pushed_authorization_request_limit")]
    pub pushed_authorization_request_limit: i32,
    #[serde(default = "default_pushed_authorization_request_window")]
    pub pushed_authorization_request_window: i32,
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    #[serde(default = "default_token_lifetime")]
    pub id_token_lifetime: i64,
    #[serde(default = "default_token_lifetime")]
    pub access_token_lifetime: i64,
    #[serde(default = "default_access_token_format")]
    pub access_token_format: String,
    #[serde(default = "default_refresh_token_lifetime")]
    pub refresh_token_lifetime: i64,
    #[serde(default = "default_clock_skew")]
    pub clock_skew: i64,
    #[serde(default)]
    pub dpop_nonce_required: bool,
    #[serde(default = "default_dpop_nonce_lifetime")]
    pub dpop_nonce_lifetime: i64,
    #[serde(default = "default_device_code_lifetime")]
    pub device_code_lifetime: i64,
    #[serde(default = "default_device_poll_interval")]
    pub device_poll_interval: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_rotation_interval: Option<i64>,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            authorization_code_lifetime: default_authorization_code_lifetime(),
            browser_authorization_lifetime: default_browser_authorization_lifetime(),
            pushed_authorization_request_lifetime: default_pushed_authorization_request_lifetime(),
            pushed_authorization_request_limit: default_pushed_authorization_request_limit(),
            pushed_authorization_request_window: default_pushed_authorization_request_window(),
            require_pushed_authorization_requests: false,
            id_token_lifetime: default_token_lifetime(),
            access_token_lifetime: default_token_lifetime(),
            access_token_format: default_access_token_format(),
            refresh_token_lifetime: default_refresh_token_lifetime(),
            clock_skew: default_clock_skew(),
            dpop_nonce_required: false,
            dpop_nonce_lifetime: default_dpop_nonce_lifetime(),
            device_code_lifetime: default_device_code_lifetime(),
            device_poll_interval: default_device_poll_interval(),
            signing_key_rotation_interval: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationPolicy {
    #[serde(default = "default_authentication_methods")]
    pub methods: Vec<String>,
    #[serde(default)]
    pub session: SessionPolicy,
    #[serde(default)]
    pub rate_limit: RateLimitPolicy,
}

impl Default for AuthenticationPolicy {
    fn default() -> Self {
        Self {
            methods: default_authentication_methods(),
            session: SessionPolicy::default(),
            rate_limit: RateLimitPolicy::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPolicy {
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: i64,
    #[serde(default = "default_absolute_timeout")]
    pub absolute_timeout: i64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: i64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: default_idle_timeout(),
            absolute_timeout: default_absolute_timeout(),
            max_concurrent: default_max_concurrent(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitPolicy {
    #[serde(default = "default_rate_limit_attempts")]
    pub attempts: i32,
    #[serde(default = "default_rate_limit_window")]
    pub window_seconds: i32,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            attempts: default_rate_limit_attempts(),
            window_seconds: default_rate_limit_window(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationPolicy {
    #[serde(default = "default_deletion_policy")]
    pub deletion_policy: String,
}

impl Default for ReconciliationPolicy {
    fn default() -> Self {
        Self {
            deletion_policy: default_deletion_policy(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfiguration {
    pub database_path: serde_json::Value,
    pub pool_size: i64,
    pub signing_key_path: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfiguration {
    pub log_level: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Branding {
    #[serde(default = "default_product_name")]
    pub product_name: String,
    #[serde(default = "default_primary_color")]
    pub primary_color: String,
    pub logo: Option<String>,
    pub favicon: Option<String>,
    pub font_family: Option<String>,
    pub support_url: Option<String>,
    pub privacy_url: Option<String>,
    pub terms_url: Option<String>,
    #[serde(default = "default_locale")]
    pub default_locale: String,
    #[serde(default = "default_locales")]
    pub locales: Vec<String>,
    #[serde(default)]
    pub messages: std::collections::HashMap<String, std::collections::HashMap<String, String>>,
}

impl Default for Branding {
    fn default() -> Self {
        Self {
            product_name: default_product_name(),
            primary_color: default_primary_color(),
            logo: None,
            favicon: None,
            font_family: None,
            support_url: None,
            privacy_url: None,
            terms_url: None,
            default_locale: default_locale(),
            locales: default_locales(),
            messages: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrandingOverride {
    pub product_name: Option<String>,
    pub primary_color: Option<String>,
    pub logo: Option<String>,
    pub favicon: Option<String>,
    pub font_family: Option<String>,
    pub support_url: Option<String>,
    pub privacy_url: Option<String>,
    pub terms_url: Option<String>,
    pub default_locale: Option<String>,
    pub locales: Option<Vec<String>>,
    #[serde(default)]
    pub messages: std::collections::HashMap<String, std::collections::HashMap<String, String>>,
}

#[derive(Clone, Debug)]
pub struct UiMessages {
    pub locale: String,
    pub sign_in_title: String,
    pub sign_in_intro: String,
    pub sign_in_identifier: String,
    pub sign_in_password: String,
    pub sign_in_submit: String,
    pub sign_in_error_title: String,
    pub sign_in_invalid_credentials: String,
    pub sign_in_mfa_required: String,
    pub sign_in_rate_limited: String,
    pub sign_in_show_password: String,
    pub sign_in_hide_password: String,
    pub sign_in_privacy_note: String,
    pub totp_title: String,
    pub totp_intro: String,
    pub totp_code: String,
    pub totp_submit: String,
    pub totp_invalid_code: String,
    pub totp_expired: String,
    pub consent_title: String,
    pub consent_intro: String,
    pub consent_approve: String,
    pub consent_deny: String,
    pub consent_sign_out_note: String,
    pub device_title: String,
    pub device_intro: String,
    pub device_code: String,
    pub device_continue: String,
    pub device_invalid_code: String,
    pub device_confirm_title: String,
    pub device_confirm_intro: String,
    pub device_possession_note: String,
    pub device_approved_title: String,
    pub device_approved_intro: String,
    pub device_denied_title: String,
    pub device_denied_intro: String,
    pub scope_openid: String,
    pub scope_profile: String,
    pub scope_email: String,
    pub scope_offline_access: String,
    pub scope_custom_prefix: String,
    pub logout_title: String,
    pub logout_intro: String,
    pub logout_submit: String,
    pub signed_out_title: String,
    pub signed_out_intro: String,
    pub return_home: String,
    pub error_title: String,
    pub error_reference: String,
    pub legal_navigation: String,
    pub support: String,
    pub privacy: String,
    pub terms: String,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub configuration: RootConfiguration,
    pub revision: String,
}

#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("cannot read configuration {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("configuration error: {0}")]
    Invalid(String),
}

impl Snapshot {
    pub fn load() -> Result<Self, ConfigurationError> {
        let root_path = env::var("ROBINE_ID_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config/robine_id.json"));

        let root_contents = match env::var("ROBINE_ID_CONFIG_JSON") {
            Ok(contents) => contents,
            Err(_) => match fs::read_to_string(&root_path) {
                Ok(contents) => contents,
                Err(source)
                    if env::var_os("VERCEL").is_some()
                        && source.kind() == std::io::ErrorKind::NotFound =>
                {
                    EMBEDDED_ROOT.to_owned()
                }
                Err(source) => {
                    return Err(ConfigurationError::Read {
                        path: root_path,
                        source,
                    });
                }
            },
        };

        if let Ok(applications_json) = env::var("ROBINE_ID_APPLICATIONS_JSON") {
            let environment_path = PathBuf::from("ROBINE_ID_APPLICATIONS_JSON");
            let applications = serde_json::from_str::<Vec<serde_json::Value>>(&applications_json)
                .map_err(|source| ConfigurationError::Json {
                    path: environment_path.clone(),
                    source,
                })?
                .into_iter()
                .enumerate()
                .map(|(index, document)| {
                    (
                        PathBuf::from(format!("ROBINE_ID_APPLICATIONS_JSON[{index}]")),
                        serde_json::to_string(&document).expect("JSON value serializes"),
                    )
                })
                .collect();
            return Self::from_application_sources(&root_path, &root_contents, applications);
        }

        let applications_path = env::var("ROBINE_ID_APPLICATIONS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                root_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("applications")
            });

        Self::from_sources(&root_path, &root_contents, &applications_path)
    }

    pub fn from_sources(
        root_path: &std::path::Path,
        root_contents: &str,
        applications_path: &std::path::Path,
    ) -> Result<Self, ConfigurationError> {
        let mut applications = Vec::new();
        if applications_path.is_dir() {
            let entries =
                fs::read_dir(applications_path).map_err(|source| ConfigurationError::Read {
                    path: applications_path.to_owned(),
                    source,
                })?;
            let mut paths = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "json")
                })
                .collect::<Vec<_>>();
            paths.sort();

            for path in paths {
                let contents =
                    fs::read_to_string(&path).map_err(|source| ConfigurationError::Read {
                        path: path.clone(),
                        source,
                    })?;
                applications.push((path, contents));
            }
        }

        Self::from_application_sources(root_path, root_contents, applications)
    }

    pub fn load_path(root_path: &std::path::Path) -> Result<Self, ConfigurationError> {
        let root_contents =
            fs::read_to_string(root_path).map_err(|source| ConfigurationError::Read {
                path: root_path.to_owned(),
                source,
            })?;
        let applications_path = root_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("applications");
        Self::from_sources(root_path, &root_contents, &applications_path)
    }

    fn from_application_sources(
        root_path: &std::path::Path,
        root_contents: &str,
        applications: Vec<(PathBuf, String)>,
    ) -> Result<Self, ConfigurationError> {
        let mut configuration: RootConfiguration =
            serde_json::from_str(root_contents).map_err(|source| ConfigurationError::Json {
                path: root_path.to_owned(),
                source,
            })?;

        if configuration.schema_version != 1 {
            return Err(ConfigurationError::Invalid(format!(
                "{}: schema_version must be 1",
                root_path.display()
            )));
        }

        for client in &mut configuration.clients {
            if client.name.is_empty() {
                client.name = client.id.clone();
            }
        }

        for (path, contents) in applications {
            let mut document: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&contents).map_err(|source| ConfigurationError::Json {
                    path: path.clone(),
                    source,
                })?;
            let schema_version = document.remove("schema_version");
            let kind = document.remove("kind");
            if schema_version != Some(serde_json::Value::from(1))
                || kind.as_ref().and_then(serde_json::Value::as_str) != Some("oidc_application")
            {
                return Err(ConfigurationError::Invalid(format!(
                    "{} must be an oidc_application with schema_version 1",
                    path.display()
                )));
            }
            let mut client = serde_json::from_value::<Client>(serde_json::Value::Object(document))
                .map_err(|source| ConfigurationError::Json {
                    path: path.clone(),
                    source,
                })?;
            if client.name.is_empty() {
                client.name = client.id.clone();
            }
            configuration.clients.push(client);
        }

        validate(&configuration).map_err(|error| match error {
            ConfigurationError::Invalid(message) => {
                ConfigurationError::Invalid(format!("{}: {message}", root_path.display()))
            }
            error => error,
        })?;

        let canonical = canonicalize(
            serde_json::to_value(&configuration).expect("configuration always serializes"),
        );
        let mut fingerprint = Sha256::new();
        fingerprint.update(
            serde_json::to_vec(&canonical).expect("canonical configuration always serializes"),
        );

        Ok(Self {
            configuration,
            revision: hex::encode(fingerprint.finalize()),
        })
    }

    pub fn redacted(&self) -> serde_json::Value {
        redact_value(
            serde_json::to_value(&self.configuration).expect("configuration always serializes"),
        )
    }

    pub fn issuer(&self, id: &str) -> Option<&Issuer> {
        self.configuration
            .issuers
            .iter()
            .find(|issuer| issuer.id == id)
    }

    pub fn client(&self, id: &str) -> Option<&Client> {
        self.configuration
            .clients
            .iter()
            .find(|client| client.id == id)
    }

    pub fn default_issuer(&self) -> Option<&Issuer> {
        self.configuration
            .issuers
            .iter()
            .min_by(|left, right| left.id.cmp(&right.id))
    }

    pub fn user_by_identifier(&self, identifier: &str) -> Option<&User> {
        let normalized = identifier.trim().to_lowercase();
        self.configuration
            .users
            .iter()
            .find(|user| user.identifier.trim().to_lowercase() == normalized)
    }

    pub fn user(&self, id: &str) -> Option<&User> {
        self.configuration.users.iter().find(|user| user.id == id)
    }

    pub fn dummy_password_hash(&self) -> &str {
        self.configuration
            .users
            .first()
            .map_or(FALLBACK_DUMMY_PASSWORD_HASH, |user| {
                user.password_hash.as_str()
            })
    }

    pub fn branding(&self, issuer_id: Option<&str>, client_id: Option<&str>) -> Branding {
        let mut branding = self.configuration.branding.clone();
        if let Some(overrides) = issuer_id
            .and_then(|id| self.issuer(id))
            .and_then(|issuer| issuer.branding.as_ref())
        {
            branding.apply(overrides);
        }
        if let Some(overrides) = client_id
            .and_then(|id| self.client(id))
            .and_then(|client| client.branding.as_ref())
        {
            branding.apply(overrides);
        }
        branding.logo = versioned_asset(branding.logo, &self.revision);
        branding.favicon = versioned_asset(branding.favicon, &self.revision);
        branding
    }
}

impl Branding {
    fn apply(&mut self, overrides: &BrandingOverride) {
        macro_rules! replace_value {
            ($field:ident) => {
                if let Some(value) = &overrides.$field {
                    self.$field = value.clone();
                }
            };
        }
        macro_rules! replace_optional {
            ($field:ident) => {
                if let Some(value) = &overrides.$field {
                    self.$field = Some(value.clone());
                }
            };
        }
        replace_value!(product_name);
        replace_value!(primary_color);
        replace_optional!(logo);
        replace_optional!(favicon);
        replace_optional!(font_family);
        replace_optional!(support_url);
        replace_optional!(privacy_url);
        replace_optional!(terms_url);
        replace_value!(default_locale);
        replace_value!(locales);
        for (locale, messages) in &overrides.messages {
            self.messages
                .entry(locale.clone())
                .or_default()
                .extend(messages.clone());
        }
    }

    pub fn messages(&self, requested_locales: Option<&str>) -> UiMessages {
        let requested_locale = requested_locales
            .into_iter()
            .flat_map(str::split_ascii_whitespace)
            .find(|locale| self.locales.iter().any(|supported| supported == locale));
        let value = |key: &str, fallback: &str| {
            requested_locale
                .and_then(|locale| self.messages.get(locale))
                .and_then(|messages| messages.get(key))
                .or_else(|| {
                    self.messages
                        .get(&self.default_locale)
                        .and_then(|messages| messages.get(key))
                })
                .cloned()
                .unwrap_or_else(|| fallback.to_owned())
        };
        UiMessages {
            locale: requested_locale.unwrap_or(&self.default_locale).to_owned(),
            sign_in_title: value("sign_in.title", "Welcome back"),
            sign_in_intro: value("sign_in.intro", "Sign in to continue"),
            sign_in_identifier: value("sign_in.identifier", "Email address"),
            sign_in_password: value("sign_in.password", "Password"),
            sign_in_submit: value("sign_in.submit", "Continue"),
            sign_in_error_title: value("sign_in.error_title", "We couldn't sign you in"),
            sign_in_invalid_credentials: value(
                "sign_in.invalid_credentials",
                "The email or password is incorrect.",
            ),
            sign_in_mfa_required: value(
                "sign_in.mfa_required",
                "This application requires an account protected by multi-factor authentication.",
            ),
            sign_in_rate_limited: value(
                "sign_in.rate_limited",
                "Too many attempts. Please wait before trying again.",
            ),
            sign_in_show_password: value("sign_in.show_password", "Show"),
            sign_in_hide_password: value("sign_in.hide_password", "Hide"),
            sign_in_privacy_note: value(
                "sign_in.privacy_note",
                "Your password is never shared with this application.",
            ),
            totp_title: value("totp.title", "Verify it's you"),
            totp_intro: value(
                "totp.intro",
                "Enter the six-digit code from your authenticator app.",
            ),
            totp_code: value("totp.code", "Authentication code"),
            totp_submit: value("totp.submit", "Verify code"),
            totp_invalid_code: value(
                "totp.invalid_code",
                "That authentication code is invalid. Try a current code.",
            ),
            totp_expired: value(
                "totp.expired",
                "This verification has expired; please sign in again.",
            ),
            consent_title: value("consent.title", "Allow access?"),
            consent_intro: value(
                "consent.intro",
                "This application would like permission to:",
            ),
            consent_approve: value("consent.approve", "Allow access"),
            consent_deny: value("consent.deny", "Cancel"),
            consent_sign_out_note: value("consent.sign_out_note", "You can sign out at any time."),
            device_title: value("device.title", "Connect a device"),
            device_intro: value(
                "device.intro",
                "Enter the code displayed by the device you are connecting.",
            ),
            device_code: value("device.code", "Device code"),
            device_continue: value("device.continue", "Continue"),
            device_invalid_code: value(
                "device.invalid_code",
                "This device code is invalid or has expired.",
            ),
            device_confirm_title: value("device.confirm_title", "Confirm this device"),
            device_confirm_intro: value(
                "device.confirm_intro",
                "Review the access requested by this device before continuing.",
            ),
            device_possession_note: value(
                "device.possession_note",
                "Approve only if this code matches a device in your possession.",
            ),
            device_approved_title: value("device.approved_title", "Device connected"),
            device_approved_intro: value(
                "device.approved_intro",
                "You can safely return to your device.",
            ),
            device_denied_title: value("device.denied_title", "Access denied"),
            device_denied_intro: value(
                "device.denied_intro",
                "The device was not connected. You can close this page.",
            ),
            scope_openid: value("scope.openid", "Confirm your identity"),
            scope_profile: value("scope.profile", "View your name and profile information"),
            scope_email: value("scope.email", "View your email address"),
            scope_offline_access: value("scope.offline_access", "Stay connected when you are away"),
            scope_custom_prefix: value("scope.custom_prefix", "Access"),
            logout_title: value("logout.title", "Sign out?"),
            logout_intro: value("logout.intro", "This ends your session on this device."),
            logout_submit: value("logout.submit", "Sign out"),
            signed_out_title: value("signed_out.title", "You're signed out"),
            signed_out_intro: value(
                "signed_out.intro",
                "Your session on this device has ended safely.",
            ),
            return_home: value("navigation.return_home", "Return home"),
            error_title: value("error.title", "Authorization request rejected"),
            error_reference: value("error.reference", "Reference"),
            legal_navigation: value("legal.navigation", "Legal and support"),
            support: value("legal.support", "Support"),
            privacy: value("legal.privacy", "Privacy"),
            terms: value("legal.terms", "Terms"),
        }
    }
}

fn validate(configuration: &RootConfiguration) -> Result<(), ConfigurationError> {
    if configuration.issuers.is_empty() {
        return Err(ConfigurationError::Invalid(
            "at least one issuer is required".to_owned(),
        ));
    }
    if configuration.issuers.len() > MAX_RESOURCES
        || configuration.clients.len() > MAX_RESOURCES
        || configuration.users.len() > MAX_RESOURCES
        || configuration.claims.len() > MAX_RESOURCES
    {
        return Err(ConfigurationError::Invalid(format!(
            "configuration collections cannot exceed {MAX_RESOURCES} resources"
        )));
    }

    validate_branding(
        &configuration.branding.primary_color,
        &configuration.branding.default_locale,
        &configuration.branding.locales,
        configuration.branding.font_family.as_deref(),
    )?;
    validate_branding_content(
        &configuration.branding.product_name,
        &configuration.branding.messages,
    )?;
    validate_branding_urls(
        configuration.branding.logo.as_deref(),
        configuration.branding.favicon.as_deref(),
        configuration.branding.support_url.as_deref(),
        configuration.branding.privacy_url.as_deref(),
        configuration.branding.terms_url.as_deref(),
    )?;
    let mut issuer_ids = std::collections::HashSet::new();
    for issuer in &configuration.issuers {
        if !valid_route_identifier(&issuer.id) || issuer.url.trim_end_matches('/').is_empty() {
            return Err(ConfigurationError::Invalid(
                "every issuer requires a URL-safe id and non-empty URL".to_owned(),
            ));
        }
        if !issuer_ids.insert(&issuer.id) {
            return Err(ConfigurationError::Invalid(format!(
                "duplicate issuer id {}",
                issuer.id
            )));
        }
        validate_issuer_url(issuer)?;
        if let Some(branding) = &issuer.branding {
            validate_branding_override(branding)?;
        }
        if !issuer.scopes.iter().any(|scope| scope == "openid") {
            return Err(ConfigurationError::Invalid(format!(
                "issuer {} must support the openid scope",
                issuer.id
            )));
        }
        if issuer.scopes.len() > 256 || !valid_scope_list(&issuer.scopes) {
            return Err(ConfigurationError::Invalid(format!(
                "issuer {} scopes must be unique valid OAuth scope tokens",
                issuer.id
            )));
        }
        let policy = &issuer.token_policy;
        if !(1..=86_400).contains(&policy.authorization_code_lifetime)
            || !(60..=3_600).contains(&policy.browser_authorization_lifetime)
            || !(10..=600).contains(&policy.pushed_authorization_request_lifetime)
            || !(1..=10_000).contains(&policy.pushed_authorization_request_limit)
            || !(1..=86_400).contains(&policy.pushed_authorization_request_window)
            || !(1..=86_400).contains(&policy.id_token_lifetime)
            || !(1..=86_400).contains(&policy.access_token_lifetime)
            || !(60..=31_536_000).contains(&policy.refresh_token_lifetime)
            || !(1..=86_400).contains(&policy.clock_skew)
            || !(30..=3_600).contains(&policy.dpop_nonce_lifetime)
            || !(300..=1_800).contains(&policy.device_code_lifetime)
            || !(5..=60).contains(&policy.device_poll_interval)
            || !matches!(policy.access_token_format.as_str(), "opaque" | "jwt")
            || policy
                .signing_key_rotation_interval
                .is_some_and(|interval| !(3_600..=31_536_000).contains(&interval))
        {
            return Err(ConfigurationError::Invalid(
                "authorization codes and short-lived tokens must use 1 to 86400 seconds, browser authorization transactions 60 to 3600 seconds, pushed authorization requests 10 to 600 seconds with a limit from 1 to 10000 and a window from 1 to 86400 seconds, device codes must use 300 to 1800 seconds with a polling interval from 5 to 60 seconds, refresh tokens 60 to 31536000 seconds, clock_skew must be positive, access_token_format must be opaque or jwt, DPoP nonces must use 30 to 3600 seconds, and signing-key rotation must use 3600 to 31536000 seconds"
                    .to_owned(),
            ));
        }
    }

    let mut client_ids = std::collections::HashSet::new();
    for client in &configuration.clients {
        if client.id.is_empty()
            || client.id.len() > MAX_IDENTIFIER_LENGTH
            || client.name.is_empty()
            || client.name.len() > MAX_DISPLAY_TEXT_LENGTH
        {
            return Err(ConfigurationError::Invalid(
                "every client requires bounded non-empty id and name values".to_owned(),
            ));
        }
        if !client_ids.insert(&client.id) {
            return Err(ConfigurationError::Invalid(format!(
                "duplicate client id {}",
                client.id
            )));
        }
        if !matches!(client.client_type.as_str(), "public" | "confidential") {
            return Err(ConfigurationError::Invalid(format!(
                "client {} has an unsupported type",
                client.id
            )));
        }
        if let Some(branding) = &client.branding {
            validate_branding_override(branding)?;
        }
        let authorization_code_enabled = client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code");
        let device_code_enabled = client
            .grant_types
            .iter()
            .any(|grant| grant == DEVICE_CODE_GRANT);
        if authorization_code_enabled
            && (!client.scopes.iter().any(|scope| scope == "openid")
                || client.redirect_uris.is_empty())
        {
            return Err(ConfigurationError::Invalid(format!(
                "client {} must allow openid and declare a redirect URI for authorization_code",
                client.id
            )));
        }
        if client.require_pushed_authorization_requests && !authorization_code_enabled {
            return Err(ConfigurationError::Invalid(format!(
                "client {} can require pushed authorization requests only with authorization_code",
                client.id
            )));
        }
        if device_code_enabled && !client.scopes.iter().any(|scope| scope == "openid") {
            return Err(ConfigurationError::Invalid(format!(
                "client {} must allow openid for the device authorization grant",
                client.id
            )));
        }
        if !valid_scope_list(&client.scopes)
            || client.scopes.len() > 256
            || client.redirect_uris.len() > 256
            || client.post_logout_redirect_uris.len() > 256
            || client.resources.len() > 256
            || client.scopes.iter().any(|scope| {
                !configuration
                    .issuers
                    .iter()
                    .any(|issuer| issuer.scopes.contains(scope))
            })
        {
            return Err(ConfigurationError::Invalid(format!(
                "client {} scopes must be unique valid tokens supported by at least one issuer",
                client.id
            )));
        }
        if client.grant_types.iter().any(|grant| {
            !matches!(
                grant.as_str(),
                "authorization_code"
                    | "refresh_token"
                    | "client_credentials"
                    | "urn:ietf:params:oauth:grant-type:token-exchange"
                    | DEVICE_CODE_GRANT
            )
        }) || client.grant_types.is_empty()
            || !unique_strings(&client.grant_types)
        {
            return Err(ConfigurationError::Invalid(format!(
                "client {} has an unsupported grant type",
                client.id
            )));
        }
        if !unique_strings(&client.redirect_uris)
            || !unique_strings(&client.post_logout_redirect_uris)
            || !unique_strings(&client.resources)
        {
            return Err(ConfigurationError::Invalid(format!(
                "client {} redirect URI lists must not contain duplicates",
                client.id
            )));
        }
        for redirect_uri in client
            .redirect_uris
            .iter()
            .chain(&client.post_logout_redirect_uris)
        {
            validate_web_url(redirect_uri, "client redirect URI")?;
        }
        for resource in &client.resources {
            validate_web_url(resource, "client resource URI")?;
        }
        if client.client_type == "confidential"
            && match client.authentication_method.as_deref() {
                None | Some("client_secret_basic" | "client_secret_post") => {
                    !client
                        .secret_reference
                        .as_ref()
                        .is_some_and(valid_secret_reference)
                        || client.jwks.is_some()
                }
                Some("private_key_jwt") => {
                    client.secret_reference.is_some()
                        || !client.jwks.as_ref().is_some_and(valid_client_jwks)
                }
                Some(_) => true,
            }
        {
            return Err(ConfigurationError::Invalid(format!(
                "confidential client {} requires a supported authentication method and matching secret reference or JWKS credential configuration",
                client.id
            )));
        }
        if client.client_type == "public"
            && (!matches!(client.authentication_method.as_deref(), None | Some("none"))
                || client.secret_reference.is_some()
                || client.jwks.is_some())
        {
            return Err(ConfigurationError::Invalid(format!(
                "public client {} cannot configure a client secret",
                client.id
            )));
        }
        if client.client_type == "public"
            && (client.pkce_required == Some(false) || client.nonce_required == Some(false))
        {
            return Err(ConfigurationError::Invalid(format!(
                "public client {} must require PKCE and nonce",
                client.id
            )));
        }
        if client
            .grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
            && client.client_type != "confidential"
        {
            return Err(ConfigurationError::Invalid(format!(
                "client {} must be confidential to use client_credentials",
                client.id
            )));
        }
        if client
            .grant_types
            .iter()
            .any(|grant| grant == "urn:ietf:params:oauth:grant-type:token-exchange")
            && (client.client_type != "confidential" || client.resources.is_empty())
        {
            return Err(ConfigurationError::Invalid(format!(
                "client {} must be confidential and declare a resource to use token exchange",
                client.id
            )));
        }
        if client
            .grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
            && !client.scopes.iter().any(|scope| {
                scope != "openid"
                    && scope != "offline_access"
                    && !configuration
                        .claims
                        .values()
                        .any(|mapping| mapping.scope == *scope)
            })
        {
            return Err(ConfigurationError::Invalid(format!(
                "client {} requires at least one non-identity scope for client_credentials",
                client.id
            )));
        }
        if client.introspection_allowed && client.client_type != "confidential" {
            return Err(ConfigurationError::Invalid(format!(
                "client {} must be confidential to use token introspection",
                client.id
            )));
        }
    }

    for issuer in &configuration.issuers {
        let mut issuer_branding = configuration.branding.clone();
        if let Some(overrides) = &issuer.branding {
            issuer_branding.apply(overrides);
        }
        validate_branding(
            &issuer_branding.primary_color,
            &issuer_branding.default_locale,
            &issuer_branding.locales,
            issuer_branding.font_family.as_deref(),
        )?;
        validate_branding_content(&issuer_branding.product_name, &issuer_branding.messages)?;
        for client in &configuration.clients {
            let mut resolved = issuer_branding.clone();
            if let Some(overrides) = &client.branding {
                resolved.apply(overrides);
            }
            validate_branding(
                &resolved.primary_color,
                &resolved.default_locale,
                &resolved.locales,
                resolved.font_family.as_deref(),
            )?;
            validate_branding_content(&resolved.product_name, &resolved.messages)?;
        }
    }

    let mut user_ids = std::collections::HashSet::new();
    let mut identifiers = std::collections::HashSet::new();
    let mut password_cost = None;
    for user in &configuration.users {
        let identifier = user.identifier.trim().to_lowercase();
        let user_password_cost = bcrypt_cost(&user.password_hash);
        if user.id.is_empty()
            || user.id.len() > MAX_IDENTIFIER_LENGTH
            || identifier.is_empty()
            || identifier.len() > 320
            || user
                .name
                .as_deref()
                .is_some_and(|name| name.is_empty() || name.len() > MAX_DISPLAY_TEXT_LENGTH)
            || user
                .email
                .as_deref()
                .is_some_and(|email| email.is_empty() || email.len() > 320)
            || user.claims.len() > 256
            || user.claims.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > MAX_IDENTIFIER_LENGTH
                    || serde_json::to_vec(value).is_ok_and(|value| value.len() > 65_536)
            })
            || user_password_cost.is_none()
            || !user_ids.insert(&user.id)
            || !identifiers.insert(identifier)
        {
            return Err(ConfigurationError::Invalid(
                "users require unique non-empty ids and identifiers plus a bcrypt hash with cost 10 through 16"
                    .to_owned(),
            ));
        }
        if password_cost.is_some_and(|configured_cost| Some(configured_cost) != user_password_cost)
        {
            return Err(ConfigurationError::Invalid(
                "all user bcrypt hashes must use the same cost to preserve constant-work authentication"
                    .to_owned(),
            ));
        }
        password_cost = user_password_cost;
    }
    for (claim, mapping) in &configuration.claims {
        if matches!(
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
                | "client_id"
                | "scope"
                | "cnf"
        ) {
            return Err(ConfigurationError::Invalid(format!(
                "claim {claim} is reserved by OpenID Connect"
            )));
        }
        if claim.is_empty()
            || claim.len() > MAX_IDENTIFIER_LENGTH
            || mapping.source.is_empty()
            || mapping.source.len() > MAX_IDENTIFIER_LENGTH
            || !valid_scope_token(&mapping.scope)
            || !configuration
                .issuers
                .iter()
                .any(|issuer| issuer.scopes.contains(&mapping.scope))
        {
            return Err(ConfigurationError::Invalid(
                "claim mappings require non-empty claims and sources plus an issuer-supported scope"
                    .to_owned(),
            ));
        }
    }

    let session = &configuration.authentication.session;
    if configuration.authentication.methods.is_empty()
        || !configuration
            .authentication
            .methods
            .iter()
            .any(|method| method == "password")
        || configuration
            .authentication
            .methods
            .iter()
            .any(|method| !matches!(method.as_str(), "password" | "totp"))
        || configuration
            .authentication
            .methods
            .iter()
            .enumerate()
            .any(|(index, method)| {
                configuration.authentication.methods[..index]
                    .iter()
                    .any(|candidate| candidate == method)
            })
    {
        return Err(ConfigurationError::Invalid(
            "authentication methods must contain password and may contain totp once".to_owned(),
        ));
    }
    let totp_enabled = configuration
        .authentication
        .methods
        .iter()
        .any(|method| method == "totp");
    for client in &configuration.clients {
        if let Some(required_acr) = client.required_acr.as_deref() {
            if !matches!(required_acr, PASSWORD_ACR | MFA_ACR)
                || !client
                    .grant_types
                    .iter()
                    .any(|grant| matches!(grant.as_str(), "authorization_code" | DEVICE_CODE_GRANT))
            {
                return Err(ConfigurationError::Invalid(format!(
                    "client {} required_acr must be a supported value on an interactive grant",
                    client.id
                )));
            }
            if required_acr == MFA_ACR && !totp_enabled {
                return Err(ConfigurationError::Invalid(format!(
                    "client {} requires the TOTP authentication context but authentication methods does not enable totp",
                    client.id
                )));
            }
        }
    }
    for user in &configuration.users {
        if user.totp_secret_reference.is_some() && !totp_enabled {
            return Err(ConfigurationError::Invalid(format!(
                "user {} configures TOTP but authentication methods does not enable totp",
                user.id
            )));
        }
        if user
            .totp_secret_reference
            .as_ref()
            .is_some_and(|reference| !valid_secret_reference(reference))
        {
            return Err(ConfigurationError::Invalid(format!(
                "user {} has an invalid TOTP secret reference",
                user.id
            )));
        }
    }
    if !(1..=31_536_000).contains(&session.idle_timeout)
        || !(1..=31_536_000).contains(&session.absolute_timeout)
        || !(1..=1_000).contains(&session.max_concurrent)
        || session.idle_timeout > session.absolute_timeout
    {
        return Err(ConfigurationError::Invalid(
            "authentication session values must be bounded and idle_timeout cannot exceed absolute_timeout"
                .to_owned(),
        ));
    }
    let rate_limit = &configuration.authentication.rate_limit;
    if !(1..=10_000).contains(&rate_limit.attempts)
        || !(1..=86_400).contains(&rate_limit.window_seconds)
    {
        return Err(ConfigurationError::Invalid(
            "authentication rate-limit values must be within safe bounds".to_owned(),
        ));
    }

    if !matches!(
        configuration.reconciliation.deletion_policy.as_str(),
        "disable" | "retain" | "delete"
    ) {
        return Err(ConfigurationError::Invalid(
            "reconciliation deletion_policy must be disable, retain, or delete".to_owned(),
        ));
    }

    if let Some(storage) = &configuration.storage {
        let valid_database_path = match &storage.database_path {
            serde_json::Value::String(path) => !path.is_empty(),
            serde_json::Value::Object(reference) => {
                reference.len() == 2
                    && reference
                        .get("provider")
                        .and_then(serde_json::Value::as_str)
                        == Some("env")
                    && reference
                        .get("key")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(valid_environment_key)
            }
            _ => false,
        };
        if !valid_database_path || storage.pool_size <= 0 {
            return Err(ConfigurationError::Invalid(
                "storage requires a database path or typed env reference and a positive pool_size"
                    .to_owned(),
            ));
        }
        if storage
            .signing_key_path
            .as_ref()
            .is_some_and(String::is_empty)
        {
            return Err(ConfigurationError::Invalid(
                "storage signing_key_path cannot be empty".to_owned(),
            ));
        }
    }

    if configuration
        .telemetry
        .log_level
        .as_deref()
        .is_some_and(|level| !matches!(level, "debug" | "info" | "warning" | "error"))
    {
        return Err(ConfigurationError::Invalid(
            "telemetry log_level must be debug, info, warning, or error".to_owned(),
        ));
    }

    Ok(())
}

fn validate_branding_override(branding: &BrandingOverride) -> Result<(), ConfigurationError> {
    if branding
        .product_name
        .as_deref()
        .is_some_and(|name| name.is_empty() || name.len() > MAX_DISPLAY_TEXT_LENGTH)
    {
        return Err(ConfigurationError::Invalid(
            "branding product_name must be non-empty and bounded".to_owned(),
        ));
    }
    if let Some(color) = &branding.primary_color {
        validate_primary_color(color)?;
    }
    if branding.locales.as_ref().is_some_and(Vec::is_empty) {
        return Err(ConfigurationError::Invalid(
            "branding locales cannot be empty".to_owned(),
        ));
    }
    validate_font_family(branding.font_family.as_deref())?;
    validate_branding_urls(
        branding.logo.as_deref(),
        branding.favicon.as_deref(),
        branding.support_url.as_deref(),
        branding.privacy_url.as_deref(),
        branding.terms_url.as_deref(),
    )?;
    validate_messages(&branding.messages)?;
    Ok(())
}

fn validate_branding_content(
    product_name: &str,
    messages: &std::collections::HashMap<String, std::collections::HashMap<String, String>>,
) -> Result<(), ConfigurationError> {
    if product_name.is_empty() || product_name.len() > MAX_DISPLAY_TEXT_LENGTH {
        return Err(ConfigurationError::Invalid(
            "branding product_name must be non-empty and bounded".to_owned(),
        ));
    }
    validate_messages(messages)
}

fn validate_messages(
    messages: &std::collections::HashMap<String, std::collections::HashMap<String, String>>,
) -> Result<(), ConfigurationError> {
    if messages.len() > 64
        || messages.iter().any(|(locale, translations)| {
            !valid_locale(locale)
                || translations.len() > 256
                || translations.iter().any(|(key, value)| {
                    key.is_empty()
                        || key.len() > MAX_IDENTIFIER_LENGTH
                        || value.len() > MAX_DISPLAY_TEXT_LENGTH
                })
        })
    {
        return Err(ConfigurationError::Invalid(
            "branding messages must use bounded locale, key, and plain-text values".to_owned(),
        ));
    }
    Ok(())
}

fn validate_branding_urls(
    logo: Option<&str>,
    favicon: Option<&str>,
    support_url: Option<&str>,
    privacy_url: Option<&str>,
    terms_url: Option<&str>,
) -> Result<(), ConfigurationError> {
    for asset in [logo, favicon].into_iter().flatten() {
        if asset.len() > MAX_URL_LENGTH {
            return Err(ConfigurationError::Invalid(
                "branding asset URL exceeds the supported length".to_owned(),
            ));
        }
        let local_asset = asset.starts_with('/')
            && !asset.starts_with("//")
            && !asset.split('/').any(|segment| segment == "..");
        if !local_asset && validate_web_url(asset, "branding asset URL").is_err() {
            return Err(ConfigurationError::Invalid(
                "branding assets must use an absolute local path or a safe web URL".to_owned(),
            ));
        }
    }
    for link in [support_url, privacy_url, terms_url].into_iter().flatten() {
        validate_web_url(link, "branding link")?;
    }
    Ok(())
}

fn versioned_asset(asset: Option<String>, revision: &str) -> Option<String> {
    asset.map(|asset| {
        let separator = if asset.contains('?') { '&' } else { '?' };
        let short_revision = &revision[..revision.len().min(12)];
        format!("{asset}{separator}rev={short_revision}")
    })
}

fn validate_branding(
    color: &str,
    default_locale: &str,
    locales: &[String],
    font_family: Option<&str>,
) -> Result<(), ConfigurationError> {
    validate_primary_color(color)?;
    validate_font_family(font_family)?;
    if !valid_locale(default_locale)
        || locales.is_empty()
        || locales.len() > 64
        || !unique_strings(locales)
        || locales.iter().any(|locale| !valid_locale(locale))
        || !locales.iter().any(|locale| locale == default_locale)
    {
        return Err(ConfigurationError::Invalid(
            "branding default_locale must be present in locales".to_owned(),
        ));
    }
    Ok(())
}

fn validate_font_family(font_family: Option<&str>) -> Result<(), ConfigurationError> {
    if font_family.is_some_and(|value| {
        value.is_empty()
            || value.len() > 128
            || value.chars().any(|character| {
                !(character.is_alphanumeric()
                    || character.is_whitespace()
                    || matches!(character, ',' | '-' | '_' | '\'' | '"'))
            })
    }) {
        return Err(ConfigurationError::Invalid(
            "branding font_family contains unsupported CSS characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_primary_color(color: &str) -> Result<(), ConfigurationError> {
    let Some(hex) = color.strip_prefix('#').filter(|hex| hex.len() == 6) else {
        return Err(ConfigurationError::Invalid(
            "branding primary_color must be a six-digit CSS hex color".to_owned(),
        ));
    };
    let channel = |start| u8::from_str_radix(&hex[start..start + 2], 16).ok();
    let (Some(red), Some(green), Some(blue)) = (channel(0), channel(2), channel(4)) else {
        return Err(ConfigurationError::Invalid(
            "branding primary_color must be a six-digit CSS hex color".to_owned(),
        ));
    };
    let linear = |channel: u8| {
        let value = f64::from(channel) / 255.0;
        if value <= 0.03928 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    let luminance = 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue);
    let contrast = 1.05 / (luminance + 0.05);
    if contrast < 4.5 {
        return Err(ConfigurationError::Invalid(format!(
            "branding primary_color {color} has insufficient contrast with white text"
        )));
    }
    Ok(())
}

fn valid_secret_reference(reference: &serde_json::Value) -> bool {
    match reference {
        serde_json::Value::Object(reference) => {
            reference.len() == 2
                && reference
                    .get("provider")
                    .and_then(serde_json::Value::as_str)
                    == Some("env")
                && reference
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(valid_environment_key)
        }
        _ => false,
    }
}

fn bcrypt_cost(hash: &str) -> Option<u8> {
    let bytes = hash.as_bytes();
    if bytes.len() != 60 || !matches!(&bytes[..4], b"$2a$" | b"$2b$" | b"$2y$") || bytes[6] != b'$'
    {
        return None;
    }
    let cost = hash[4..6].parse::<u8>().ok()?;
    ((10..=16).contains(&cost)
        && bytes[7..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/')))
    .then_some(cost)
}

fn canonicalize(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<std::collections::BTreeMap<_, _>>();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(values) => {
            let mut values = values.into_iter().map(canonicalize).collect::<Vec<_>>();
            values.sort_by_key(|value| serde_json::to_string(value).unwrap_or_default());
            serde_json::Value::Array(values)
        }
        value => value,
    }
}

fn redact_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let normalized = key.to_ascii_lowercase();
                    let sensitive = matches!(
                        normalized.as_str(),
                        "password"
                            | "password_hash"
                            | "secret"
                            | "secret_reference"
                            | "totp_secret_reference"
                            | "client_secret"
                            | "client_assertion"
                            | "private_key"
                            | "private_key_pem"
                            | "access_token"
                            | "id_token"
                            | "refresh_token"
                            | "authorization_code"
                            | "database_path"
                    ) || normalized.ends_with("_secret");
                    (
                        key,
                        if sensitive {
                            serde_json::Value::String("[REDACTED]".to_owned())
                        } else {
                            redact_value(value)
                        },
                    )
                })
                .collect(),
        ),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(redact_value).collect())
        }
        value => value,
    }
}

fn valid_client_jwks(jwks: &ClientJwkSet) -> bool {
    if jwks.keys.is_empty() || jwks.keys.len() > 16 {
        return false;
    }
    let mut key_ids = std::collections::HashSet::new();
    jwks.keys
        .iter()
        .all(|key| key_ids.insert(&key.kid) && valid_client_jwk(key))
}

fn valid_client_jwk(key: &ClientJwk) -> bool {
    if key.kty != "RSA"
        || key.kid.is_empty()
        || key.kid.len() > 256
        || !(342..=1_368).contains(&key.n.len())
        || !(2..=16).contains(&key.e.len())
        || !key.use_.as_deref().is_none_or(|value| value == "sig")
        || !key.alg.as_deref().is_none_or(|value| value == "RS256")
    {
        return false;
    }
    let (Ok(modulus), Ok(exponent)) = (
        URL_SAFE_NO_PAD.decode(key.n.as_bytes()),
        URL_SAFE_NO_PAD.decode(key.e.as_bytes()),
    ) else {
        return false;
    };
    (256..=1_024).contains(&modulus.len())
        && (1..=8).contains(&exponent.len())
        && RsaPublicKey::new(
            BigUint::from_bytes_be(&modulus),
            BigUint::from_bytes_be(&exponent),
        )
        .is_ok()
}

fn validate_web_url(value: &str, label: &str) -> Result<(), ConfigurationError> {
    if value.len() > MAX_URL_LENGTH {
        return Err(ConfigurationError::Invalid(format!(
            "{label} exceeds the supported length"
        )));
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| ConfigurationError::Invalid(format!("{label} is invalid")))?;
    let loopback = parsed.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if (parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigurationError::Invalid(format!(
            "{label} must use HTTPS (or loopback HTTP) without credentials or fragments"
        )));
    }
    Ok(())
}

fn validate_issuer_url(issuer: &Issuer) -> Result<(), ConfigurationError> {
    validate_web_url(&issuer.url, "issuer URL")?;
    let parsed = url::Url::parse(&issuer.url)
        .map_err(|_| ConfigurationError::Invalid("issuer URL is invalid".to_owned()))?;
    let expected_path = format!("/{}", issuer.id);
    if parsed.query().is_some() || parsed.path().trim_end_matches('/') != expected_path {
        return Err(ConfigurationError::Invalid(format!(
            "issuer {} URL path must be exactly {} and cannot contain a query",
            issuer.id, expected_path
        )));
    }
    Ok(())
}

fn valid_route_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn valid_scope_list(scopes: &[String]) -> bool {
    let mut unique = std::collections::HashSet::new();
    !scopes.is_empty()
        && scopes
            .iter()
            .all(|scope| valid_scope_token(scope) && unique.insert(scope))
}

fn valid_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 128
        && scope
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn unique_strings(values: &[String]) -> bool {
    let mut unique = std::collections::HashSet::new();
    values.iter().all(|value| unique.insert(value))
}

fn valid_locale(locale: &str) -> bool {
    !locale.is_empty()
        && locale.len() <= 35
        && locale
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_environment_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && key.len() <= 128
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ]
}

fn default_client_type() -> String {
    "public".to_owned()
}

fn default_grant_types() -> Vec<String> {
    vec!["authorization_code".to_owned()]
}

fn default_product_name() -> String {
    "Robine ID".to_owned()
}

fn default_primary_color() -> String {
    "#176b70".to_owned()
}

fn default_locale() -> String {
    "en".to_owned()
}

fn default_locales() -> Vec<String> {
    vec!["en".to_owned()]
}

fn default_authorization_code_lifetime() -> i64 {
    60
}

fn default_browser_authorization_lifetime() -> i64 {
    600
}

fn default_pushed_authorization_request_lifetime() -> i64 {
    90
}

fn default_pushed_authorization_request_limit() -> i32 {
    120
}

fn default_pushed_authorization_request_window() -> i32 {
    60
}

fn default_token_lifetime() -> i64 {
    300
}

fn default_access_token_format() -> String {
    "opaque".to_owned()
}

fn default_dpop_nonce_lifetime() -> i64 {
    300
}

fn default_device_code_lifetime() -> i64 {
    600
}

fn default_device_poll_interval() -> i32 {
    5
}

fn default_refresh_token_lifetime() -> i64 {
    2_592_000
}

fn default_clock_skew() -> i64 {
    30
}

fn default_idle_timeout() -> i64 {
    1_800
}

fn default_absolute_timeout() -> i64 {
    28_800
}

fn default_max_concurrent() -> i64 {
    5
}

fn default_rate_limit_attempts() -> i32 {
    5
}

fn default_rate_limit_window() -> i32 {
    60
}

fn default_authentication_methods() -> Vec<String> {
    vec!["password".to_owned()]
}

fn default_deletion_policy() -> String {
    "disable".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use rsa::{RsaPrivateKey, traits::PublicKeyParts};
    use std::path::Path;

    #[test]
    fn loads_the_existing_configuration_shape() {
        let temporary = std::env::temp_dir().join(format!("robine-id-{}", std::process::id()));
        let snapshot = Snapshot::from_sources(
            std::path::Path::new("config/robine_id.json"),
            EMBEDDED_ROOT,
            &temporary,
        )
        .expect("configuration should load");

        assert_eq!(
            snapshot.default_issuer().map(|issuer| issuer.id.as_str()),
            Some("default")
        );
        assert_eq!(snapshot.revision.len(), 64);
    }

    #[test]
    fn derives_a_safe_signing_key_retention_window() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        let issuer = &mut configuration.issuers[0];
        issuer.token_policy.id_token_lifetime = 900;
        issuer.token_policy.access_token_lifetime = 1_200;
        issuer.token_policy.access_token_format = "jwt".to_owned();
        issuer.token_policy.clock_skew = 30;

        assert_eq!(issuer.signing_key_retention_seconds(), 1_530);
    }

    #[test]
    fn validates_the_access_token_format() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        assert_eq!(
            configuration.issuers[0].token_policy.access_token_format,
            "opaque"
        );

        configuration.issuers[0].token_policy.access_token_format = "paseto".to_owned();
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("access_token_format")
        ));

        configuration.issuers[0].token_policy.access_token_format = "jwt".to_owned();
        assert!(validate(&configuration).is_ok());
    }

    #[test]
    fn validates_optional_automatic_signing_key_rotation() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0]
            .token_policy
            .signing_key_rotation_interval = Some(3_599);
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("signing-key rotation")
        ));

        configuration.issuers[0]
            .token_policy
            .signing_key_rotation_interval = Some(3_600);
        assert!(validate(&configuration).is_ok());
    }

    #[test]
    fn bounds_pushed_authorization_request_lifetime() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        assert_eq!(
            configuration.issuers[0]
                .token_policy
                .pushed_authorization_request_lifetime,
            90
        );
        assert_eq!(
            configuration.issuers[0]
                .token_policy
                .pushed_authorization_request_limit,
            120
        );
        assert_eq!(
            configuration.issuers[0]
                .token_policy
                .pushed_authorization_request_window,
            60
        );
        assert_eq!(
            configuration.issuers[0]
                .token_policy
                .browser_authorization_lifetime,
            600
        );
        assert!(
            !configuration.issuers[0]
                .token_policy
                .require_pushed_authorization_requests
        );
        configuration.issuers[0]
            .token_policy
            .browser_authorization_lifetime = 59;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("browser authorization transactions")
        ));
        configuration.issuers[0]
            .token_policy
            .browser_authorization_lifetime = 600;
        configuration.issuers[0]
            .token_policy
            .pushed_authorization_request_lifetime = 9;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("pushed authorization requests")
        ));
        configuration.issuers[0]
            .token_policy
            .pushed_authorization_request_lifetime = 600;
        configuration.issuers[0]
            .token_policy
            .pushed_authorization_request_limit = 0;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("pushed authorization requests")
        ));
        configuration.issuers[0]
            .token_policy
            .pushed_authorization_request_limit = 120;
        configuration.issuers[0]
            .token_policy
            .pushed_authorization_request_window = 86_401;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("pushed authorization requests")
        ));
        configuration.issuers[0]
            .token_policy
            .pushed_authorization_request_window = 60;
        assert!(validate(&configuration).is_ok());
    }

    #[test]
    fn configures_bounded_optional_dpop_nonces() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        let policy = &mut configuration.issuers[0].token_policy;
        assert!(!policy.dpop_nonce_required);
        assert_eq!(policy.dpop_nonce_lifetime, 300);

        policy.dpop_nonce_required = true;
        policy.dpop_nonce_lifetime = 29;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("DPoP nonces")
        ));
        configuration.issuers[0].token_policy.dpop_nonce_lifetime = 3_600;
        assert!(validate(&configuration).is_ok());
    }

    #[test]
    fn rejects_non_loopback_plain_http_issuer_urls() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0].url = "http://id.example/default".to_owned();

        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_issuer_urls_that_do_not_map_to_the_routed_identifier() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0].url = "https://id.example/other".to_owned();
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("must be exactly /default")
        ));

        configuration.issuers[0].url = "https://id.example/default?tenant=other".to_owned();
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("cannot contain a query")
        ));

        configuration.issuers[0].url = "https://id.example/default".to_owned();
        configuration.issuers[0].id = "nested/issuer".to_owned();
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("URL-safe id")
        ));
    }

    #[test]
    fn resolves_branding_overrides_and_message_fallbacks() {
        let mut branding = Branding::default();
        branding.messages.insert(
            "en".to_owned(),
            [("sign_in.intro".to_owned(), "Continue securely".to_owned())]
                .into_iter()
                .collect(),
        );
        branding.apply(&BrandingOverride {
            product_name: Some("Client identity".to_owned()),
            messages: [(
                "fr".to_owned(),
                [(
                    "sign_in.title".to_owned(),
                    "Heureux de vous revoir".to_owned(),
                )]
                .into_iter()
                .collect(),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        branding.locales.push("fr".to_owned());
        let messages = branding.messages(Some("fr en"));

        assert_eq!(branding.product_name, "Client identity");
        assert_eq!(messages.locale, "fr");
        assert_eq!(messages.sign_in_title, "Heureux de vous revoir");
        assert_eq!(messages.sign_in_intro, "Continue securely");
    }

    #[test]
    fn rejects_brand_colors_without_white_text_contrast() {
        assert!(matches!(
            validate_primary_color("#ffffff"),
            Err(ConfigurationError::Invalid(message)) if message.contains("insufficient contrast")
        ));
    }

    #[test]
    fn rejects_duplicate_malformed_and_unavailable_scopes() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0].scopes.push("openid".to_owned());
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("unique valid OAuth scope")
        ));

        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0]
            .scopes
            .push("invalid scope".to_owned());
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("unique valid OAuth scope")
        ));

        configuration.issuers[0].scopes.pop();
        configuration.claims.insert(
            "department".to_owned(),
            ClaimMapping {
                source: "department".to_owned(),
                scope: "organization".to_owned(),
            },
        );
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("issuer-supported scope")
        ));

        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.claims.insert(
            "at_hash".to_owned(),
            ClaimMapping {
                source: "department".to_owned(),
                scope: "openid".to_owned(),
            },
        );
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("reserved by OpenID Connect")
        ));
    }

    #[test]
    fn rejects_unbounded_configuration_values() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0].id = "i".repeat(129);
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("URL-safe id")
        ));

        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.branding.messages.insert(
            "invalid_locale!".to_owned(),
            [("sign_in.title".to_owned(), "Title".to_owned())]
                .into_iter()
                .collect(),
        );
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("branding messages")
        ));

        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.authentication.session.idle_timeout = 3_600;
        configuration.authentication.session.absolute_timeout = 60;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("idle_timeout")
        ));

        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0].token_policy.refresh_token_lifetime = 59;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("refresh tokens")
        ));
    }

    #[test]
    fn requires_one_bcrypt_cost_and_matches_unknown_user_work() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        let configured_hash = configuration.users[0].password_hash.clone();
        let snapshot = Snapshot {
            configuration: configuration.clone(),
            revision: "test".to_owned(),
        };
        assert_eq!(snapshot.dummy_password_hash(), configured_hash);

        configuration.users.push(User {
            id: "different-cost".to_owned(),
            identifier: "different-cost@example.test".to_owned(),
            password_hash: configured_hash.replacen("$2b$12$", "$2b$16$", 1),
            totp_secret_reference: None,
            name: None,
            email: None,
            claims: Default::default(),
        });
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("same cost")
        ));

        let mut empty_snapshot = snapshot;
        empty_snapshot.configuration.users.clear();
        assert_eq!(
            empty_snapshot.dummy_password_hash(),
            FALLBACK_DUMMY_PASSWORD_HASH
        );
    }

    #[test]
    fn composes_inline_application_documents_for_serverless_deployments() {
        let application = serde_json::json!({
            "schema_version": 1,
            "kind": "oidc_application",
            "id": "inline-client",
            "type": "public",
            "redirect_uris": ["https://app.example/callback"],
            "scopes": ["openid"]
        });
        let snapshot = Snapshot::from_application_sources(
            std::path::Path::new("ROBINE_ID_CONFIG_JSON"),
            EMBEDDED_ROOT,
            vec![(
                PathBuf::from("ROBINE_ID_APPLICATIONS_JSON[0]"),
                application.to_string(),
            )],
        )
        .expect("inline configuration");

        assert!(snapshot.client("inline-client").is_some());
        assert_eq!(
            snapshot
                .client("inline-client")
                .map(|client| client.name.as_str()),
            Some("inline-client")
        );
    }

    #[test]
    fn loads_the_token_exchange_application_template() {
        let mut root: serde_json::Value =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        root["issuers"][0]["scopes"] =
            serde_json::json!(["openid", "profile", "email", "service.read"]);
        let snapshot = Snapshot::from_application_sources(
            Path::new("root.json"),
            &serde_json::to_string(&root).expect("root JSON"),
            vec![(
                PathBuf::from("token-exchange-client-application.json"),
                include_str!("../config/templates/token-exchange-client-application.json")
                    .to_owned(),
            )],
        )
        .expect("token exchange template");
        let broker = snapshot
            .client("service-token-broker")
            .expect("token exchange client");
        assert!(
            broker
                .grant_types
                .iter()
                .any(|grant| { grant == "urn:ietf:params:oauth:grant-type:token-exchange" })
        );
        assert_eq!(broker.resources.len(), 2);
    }

    #[test]
    fn loads_the_device_client_application_template() {
        let mut root: serde_json::Value =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        root["issuers"][0]["scopes"] =
            serde_json::json!(["openid", "profile", "email", "offline_access"]);
        let snapshot = Snapshot::from_application_sources(
            Path::new("root.json"),
            &serde_json::to_string(&root).expect("root JSON"),
            vec![(
                PathBuf::from("device-client-application.json"),
                include_str!("../config/templates/device-client-application.json").to_owned(),
            )],
        )
        .expect("device client template");
        let client = snapshot.client("device-client").expect("device client");
        assert!(client.redirect_uris.is_empty());
        assert!(
            client
                .grant_types
                .iter()
                .any(|grant| grant == DEVICE_CODE_GRANT)
        );
        assert!(
            client
                .grant_types
                .iter()
                .any(|grant| grant == "refresh_token")
        );
    }

    #[test]
    fn loads_the_mfa_client_application_template() {
        let mut root: serde_json::Value =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        root["authentication"]["methods"] = serde_json::json!(["password", "totp"]);
        root["issuers"][0]["scopes"] =
            serde_json::json!(["openid", "profile", "email", "offline_access"]);
        let snapshot = Snapshot::from_application_sources(
            Path::new("root.json"),
            &serde_json::to_string(&root).expect("root JSON"),
            vec![(
                PathBuf::from("mfa-client-application.json"),
                include_str!("../config/templates/mfa-client-application.json").to_owned(),
            )],
        )
        .expect("MFA client template");
        assert_eq!(
            snapshot
                .client("mfa-web-client")
                .and_then(|client| client.required_acr.as_deref()),
            Some(MFA_ACR)
        );
    }

    #[test]
    fn rejects_unknown_fields_at_every_configuration_boundary() {
        let mut root: serde_json::Value =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        root.as_object_mut()
            .expect("root object")
            .insert("surprise".to_owned(), serde_json::Value::Bool(true));
        let error = Snapshot::from_application_sources(
            std::path::Path::new("unknown-root.json"),
            &root.to_string(),
            vec![],
        )
        .expect_err("unknown root field should fail");
        assert!(error.to_string().contains("unknown field `surprise`"));

        let application = serde_json::json!({
            "schema_version": 1,
            "kind": "oidc_application",
            "id": "unknown-client",
            "type": "public",
            "redirect_uris": ["https://app.example/callback"],
            "scopes": ["openid"],
            "surprise": true
        });
        let error = Snapshot::from_application_sources(
            std::path::Path::new("root.json"),
            EMBEDDED_ROOT,
            vec![(
                PathBuf::from("unknown-client.json"),
                application.to_string(),
            )],
        )
        .expect_err("unknown client field should fail");
        assert!(error.to_string().contains("unknown field `surprise`"));
    }

    #[test]
    fn fingerprints_semantic_configuration_instead_of_json_formatting() {
        let compact: serde_json::Value =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        let compact = serde_json::to_string(&compact).expect("compact JSON");
        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(EMBEDDED_ROOT)
                .expect("embedded configuration"),
        )
        .expect("pretty JSON");
        let applications = std::env::temp_dir().join("robine-id-no-applications");
        let first = Snapshot::from_sources(Path::new("first.json"), &compact, &applications)
            .expect("compact configuration");
        let second = Snapshot::from_sources(Path::new("second.json"), &pretty, &applications)
            .expect("pretty configuration");
        assert_eq!(first.revision, second.revision);
    }

    #[test]
    fn effective_configuration_redacts_secret_material() {
        let snapshot = Snapshot::from_sources(
            Path::new("config/robine_id.json"),
            EMBEDDED_ROOT,
            &std::env::temp_dir().join("robine-id-no-applications"),
        )
        .expect("configuration");
        let effective = snapshot.redacted();
        assert_eq!(
            effective["users"][0]["password_hash"],
            serde_json::Value::String("[REDACTED]".to_owned())
        );
        assert_eq!(
            effective["issuers"][0]["token_policy"]["id_token_lifetime"],
            serde_json::Value::from(300)
        );
        assert_eq!(
            effective["branding"]["messages"]["fr"]["sign_in.password"],
            serde_json::Value::String("Mot de passe".to_owned())
        );
        let secret_reference = redact_value(serde_json::json!({
            "secret_reference": {"provider": "env", "key": "CLIENT_SECRET"}
        }));
        assert_eq!(
            secret_reference["secret_reference"],
            serde_json::Value::String("[REDACTED]".to_owned())
        );
    }

    #[test]
    fn validates_and_redacts_per_user_totp_configuration() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.authentication.methods.push("totp".to_owned());
        configuration.users[0].totp_secret_reference = Some(serde_json::json!({
            "provider": "env",
            "key": "DEVELOPMENT_USER_TOTP_SECRET"
        }));
        validate(&configuration).expect("valid TOTP configuration");
        let snapshot = Snapshot {
            configuration: configuration.clone(),
            revision: "totp".to_owned(),
        };
        assert_eq!(
            snapshot.redacted()["users"][0]["totp_secret_reference"],
            serde_json::Value::String("[REDACTED]".to_owned())
        );

        configuration.authentication.methods = vec!["password".to_owned()];
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("does not enable totp")
        ));
        configuration.authentication.methods.push("totp".to_owned());
        configuration.users[0].totp_secret_reference = Some(serde_json::json!({
            "provider": "literal",
            "key": "unsafe"
        }));
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("invalid TOTP secret reference")
        ));
    }

    #[test]
    fn validates_per_client_required_authentication_context() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        let client: Client = serde_json::from_value(serde_json::json!({
            "id": "mfa-client",
            "name": "MFA client",
            "type": "public",
            "redirect_uris": ["https://app.example/callback"],
            "scopes": ["openid"],
            "grant_types": ["authorization_code"],
            "authentication_method": "none",
            "required_acr": MFA_ACR
        }))
        .expect("MFA client configuration");
        configuration.clients.push(client);

        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("does not enable totp")
        ));
        configuration.authentication.methods.push("totp".to_owned());
        validate(&configuration).expect("MFA policy with TOTP enabled");

        configuration.clients[0].required_acr = Some("urn:unsupported:acr".to_owned());
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("required_acr")
        ));
        configuration.clients[0].required_acr = Some(MFA_ACR.to_owned());
        configuration.clients[0].grant_types = vec!["refresh_token".to_owned()];
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("interactive grant")
        ));
    }

    #[test]
    fn rejects_weak_password_hashes_and_unsafe_public_client_policy() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.users[0].password_hash =
            "$2b$04$.JtidA6ZMWny4XaLMozDSOupYHbVNQurj8NkCdM9D3m/g3v3fyXXa".to_owned();
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("bcrypt")
        ));

        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.clients.push(Client {
            id: "unsafe-public".to_owned(),
            name: "Unsafe public".to_owned(),
            client_type: "public".to_owned(),
            redirect_uris: vec!["https://app.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            resources: vec![],
            scopes: vec!["openid".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            pkce_required: Some(false),
            nonce_required: None,
            consent_required: None,
            introspection_allowed: false,
            require_pushed_authorization_requests: false,
            required_acr: None,
            authentication_method: None,
            secret_reference: None,
            jwks: None,
            branding: None,
        });
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("must require PKCE")
        ));

        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.clients.push(Client {
            id: "unsafe-introspector".to_owned(),
            name: "Unsafe introspector".to_owned(),
            client_type: "public".to_owned(),
            redirect_uris: vec!["https://app.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            resources: vec![],
            scopes: vec!["openid".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            pkce_required: None,
            nonce_required: None,
            consent_required: None,
            introspection_allowed: true,
            require_pushed_authorization_requests: false,
            required_acr: None,
            authentication_method: None,
            secret_reference: None,
            jwks: None,
            branding: None,
        });
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("confidential to use token introspection")
        ));

        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.clients.push(Client {
            id: "plaintext-secret".to_owned(),
            name: "Plaintext secret".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://app.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            resources: vec![],
            scopes: vec!["openid".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            pkce_required: None,
            nonce_required: None,
            consent_required: None,
            introspection_allowed: false,
            require_pushed_authorization_requests: false,
            required_acr: None,
            authentication_method: Some("client_secret_basic".to_owned()),
            secret_reference: Some(serde_json::json!("must-not-be-inline")),
            jwks: None,
            branding: None,
        });
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("secret reference")
        ));
    }

    #[test]
    fn validates_confidential_service_clients_and_their_scopes() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0]
            .scopes
            .push("service.read".to_owned());
        let service_client = Client {
            id: "service-client".to_owned(),
            name: "Service client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            resources: vec![],
            scopes: vec!["service.read".to_owned()],
            grant_types: vec!["client_credentials".to_owned()],
            pkce_required: None,
            nonce_required: None,
            consent_required: None,
            introspection_allowed: true,
            require_pushed_authorization_requests: false,
            required_acr: None,
            authentication_method: Some("client_secret_basic".to_owned()),
            secret_reference: Some(serde_json::json!({
                "provider": "env",
                "key": "SERVICE_CLIENT_SECRET"
            })),
            jwks: None,
            branding: None,
        };
        configuration.clients.push(service_client.clone());
        assert!(validate(&configuration).is_ok());

        configuration.clients[0].require_pushed_authorization_requests = true;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("only with authorization_code")
        ));
        configuration.clients[0].require_pushed_authorization_requests = false;

        configuration
            .clients
            .last_mut()
            .expect("service client")
            .client_type = "public".to_owned();
        configuration
            .clients
            .last_mut()
            .expect("service client")
            .authentication_method = Some("none".to_owned());
        configuration
            .clients
            .last_mut()
            .expect("service client")
            .secret_reference = None;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("confidential to use client_credentials")
        ));

        let service_client = configuration.clients.last_mut().expect("service client");
        service_client.client_type = "confidential".to_owned();
        service_client.authentication_method = Some("client_secret_basic".to_owned());
        service_client.secret_reference = Some(serde_json::json!({
            "provider": "env",
            "key": "SERVICE_CLIENT_SECRET"
        }));
        service_client.scopes = vec!["openid".to_owned()];
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("non-identity scope")
        ));
    }

    #[test]
    fn validates_confidential_token_exchange_clients_and_their_targets() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0]
            .scopes
            .push("service.read".to_owned());
        let mut broker = Client {
            id: "broker".to_owned(),
            name: "Broker".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            resources: vec!["https://api.example/resource".to_owned()],
            scopes: vec!["service.read".to_owned()],
            grant_types: vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_owned()],
            pkce_required: None,
            nonce_required: None,
            consent_required: None,
            introspection_allowed: true,
            require_pushed_authorization_requests: false,
            required_acr: None,
            authentication_method: Some("client_secret_basic".to_owned()),
            secret_reference: Some(serde_json::json!({
                "provider": "env",
                "key": "BROKER_SECRET"
            })),
            jwks: None,
            branding: None,
        };
        configuration.clients.push(broker.clone());
        assert!(validate(&configuration).is_ok());

        broker.resources.clear();
        *configuration.clients.last_mut().expect("broker") = broker.clone();
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("declare a resource")
        ));

        broker.resources = vec!["https://api.example/resource".to_owned()];
        broker.client_type = "public".to_owned();
        broker.authentication_method = Some("none".to_owned());
        broker.secret_reference = None;
        *configuration.clients.last_mut().expect("broker") = broker;
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("confidential and declare a resource")
        ));
    }

    #[test]
    fn rejects_unsafe_or_duplicate_resource_uris() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.clients.push(Client {
            id: "resource-client".to_owned(),
            name: "Resource client".to_owned(),
            client_type: "public".to_owned(),
            redirect_uris: vec!["https://app.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            resources: vec![],
            scopes: vec!["openid".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            pkce_required: None,
            nonce_required: None,
            consent_required: None,
            introspection_allowed: false,
            require_pushed_authorization_requests: false,
            required_acr: None,
            authentication_method: None,
            secret_reference: None,
            jwks: None,
            branding: None,
        });
        configuration.clients[0].resources = vec!["javascript:alert(1)".to_owned()];
        assert!(validate(&configuration).is_err());

        configuration.clients[0].resources = vec![
            "https://api.example/resource".to_owned(),
            "https://api.example/resource".to_owned(),
        ];
        assert!(validate(&configuration).is_err());
    }

    #[test]
    fn validates_private_key_jwt_credentials_and_key_rotation_sets() {
        let mut configuration: RootConfiguration =
            serde_json::from_str(EMBEDDED_ROOT).expect("embedded configuration");
        configuration.issuers[0]
            .scopes
            .push("service.read".to_owned());
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key");
        let public = private.to_public_key();
        let jwk = ClientJwk {
            kty: "RSA".to_owned(),
            kid: "primary".to_owned(),
            use_: Some("sig".to_owned()),
            alg: Some("RS256".to_owned()),
            n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        };
        configuration.clients.push(Client {
            id: "assertion-client".to_owned(),
            name: "Assertion client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            resources: vec![],
            scopes: vec!["service.read".to_owned()],
            grant_types: vec!["client_credentials".to_owned()],
            pkce_required: None,
            nonce_required: None,
            consent_required: None,
            introspection_allowed: true,
            require_pushed_authorization_requests: false,
            required_acr: None,
            authentication_method: Some("private_key_jwt".to_owned()),
            secret_reference: None,
            jwks: Some(ClientJwkSet {
                keys: vec![jwk.clone()],
            }),
            branding: None,
        });
        assert!(validate(&configuration).is_ok());

        let mut rotated_jwk = jwk.clone();
        rotated_jwk.kid = "next".to_owned();
        configuration.clients.last_mut().expect("client").jwks = Some(ClientJwkSet {
            keys: vec![jwk.clone(), rotated_jwk],
        });
        assert!(validate(&configuration).is_ok());

        configuration.clients.last_mut().expect("client").jwks = Some(ClientJwkSet {
            keys: vec![jwk.clone(), jwk],
        });
        assert!(validate(&configuration).is_err());

        configuration.clients.last_mut().expect("client").jwks = Some(ClientJwkSet {
            keys: vec![ClientJwk {
                kty: "RSA".to_owned(),
                kid: "invalid".to_owned(),
                use_: Some("sig".to_owned()),
                alg: Some("RS256".to_owned()),
                n: URL_SAFE_NO_PAD.encode([0_u8; 256]),
                e: "AQAB".to_owned(),
            }],
        });
        assert!(validate(&configuration).is_err());
    }
}
