use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};
use thiserror::Error;

const EMBEDDED_ROOT: &str = include_str!("../config/robine_id.json");

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
    pub authentication_method: Option<String>,
    pub secret_reference: Option<serde_json::Value>,
    #[serde(default)]
    pub branding: Option<BrandingOverride>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub id: String,
    pub identifier: String,
    pub password_hash: String,
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
    #[serde(default = "default_token_lifetime")]
    pub id_token_lifetime: i64,
    #[serde(default = "default_token_lifetime")]
    pub access_token_lifetime: i64,
    #[serde(default = "default_clock_skew")]
    pub clock_skew: i64,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            authorization_code_lifetime: default_authorization_code_lifetime(),
            id_token_lifetime: default_token_lifetime(),
            access_token_lifetime: default_token_lifetime(),
            clock_skew: default_clock_skew(),
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
    pub sign_in_title: String,
    pub sign_in_intro: String,
    pub sign_in_identifier: String,
    pub sign_in_password: String,
    pub sign_in_submit: String,
    pub consent_title: String,
    pub consent_intro: String,
    pub consent_approve: String,
    pub consent_deny: String,
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
            return Err(ConfigurationError::Invalid(
                "schema_version must be 1".to_owned(),
            ));
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
            let client = serde_json::from_value::<Client>(serde_json::Value::Object(document))
                .map_err(|source| ConfigurationError::Json {
                    path: path.clone(),
                    source,
                })?;
            configuration.clients.push(client);
        }

        validate(&configuration)?;

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
        self.configuration.issuers.first()
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
            sign_in_title: value("sign_in.title", "Welcome back"),
            sign_in_intro: value("sign_in.intro", "Sign in to continue"),
            sign_in_identifier: value("sign_in.identifier", "Email address"),
            sign_in_password: value("sign_in.password", "Password"),
            sign_in_submit: value("sign_in.submit", "Continue"),
            consent_title: value("consent.title", "Allow access?"),
            consent_intro: value(
                "consent.intro",
                "This application would like permission to:",
            ),
            consent_approve: value("consent.approve", "Allow access"),
            consent_deny: value("consent.deny", "Cancel"),
        }
    }
}

fn validate(configuration: &RootConfiguration) -> Result<(), ConfigurationError> {
    if configuration.issuers.is_empty() {
        return Err(ConfigurationError::Invalid(
            "at least one issuer is required".to_owned(),
        ));
    }

    validate_branding(
        &configuration.branding.primary_color,
        &configuration.branding.default_locale,
        &configuration.branding.locales,
        configuration.branding.font_family.as_deref(),
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
        if issuer.id.is_empty() || issuer.url.trim_end_matches('/').is_empty() {
            return Err(ConfigurationError::Invalid(
                "every issuer requires a non-empty id and URL".to_owned(),
            ));
        }
        if !issuer_ids.insert(&issuer.id) {
            return Err(ConfigurationError::Invalid(format!(
                "duplicate issuer id {}",
                issuer.id
            )));
        }
        validate_web_url(&issuer.url, "issuer URL")?;
        if let Some(branding) = &issuer.branding {
            validate_branding_override(branding)?;
        }
        if !issuer.scopes.iter().any(|scope| scope == "openid") {
            return Err(ConfigurationError::Invalid(format!(
                "issuer {} must support the openid scope",
                issuer.id
            )));
        }
        let policy = &issuer.token_policy;
        if !(1..=86_400).contains(&policy.authorization_code_lifetime)
            || !(1..=86_400).contains(&policy.id_token_lifetime)
            || !(1..=86_400).contains(&policy.access_token_lifetime)
            || !(1..=86_400).contains(&policy.clock_skew)
        {
            return Err(ConfigurationError::Invalid(
                "token lifetimes must be between 1 and 86400 seconds and clock_skew cannot be negative"
                    .to_owned(),
            ));
        }
    }

    let mut client_ids = std::collections::HashSet::new();
    for client in &configuration.clients {
        if client.id.is_empty() || client.redirect_uris.is_empty() {
            return Err(ConfigurationError::Invalid(
                "every client requires an id and at least one redirect URI".to_owned(),
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
        if !client.scopes.iter().any(|scope| scope == "openid") {
            return Err(ConfigurationError::Invalid(format!(
                "client {} must allow the openid scope",
                client.id
            )));
        }
        if client
            .grant_types
            .iter()
            .any(|grant| grant != "authorization_code")
        {
            return Err(ConfigurationError::Invalid(format!(
                "client {} has an unsupported grant type",
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
        if client.client_type == "confidential"
            && (!matches!(
                client.authentication_method.as_deref(),
                None | Some("client_secret_basic" | "client_secret_post")
            ) || !client
                .secret_reference
                .as_ref()
                .is_some_and(valid_secret_reference))
        {
            return Err(ConfigurationError::Invalid(format!(
                "confidential client {} requires a supported authentication method and secret reference",
                client.id
            )));
        }
        if client.client_type == "public"
            && (!matches!(client.authentication_method.as_deref(), None | Some("none"))
                || client.secret_reference.is_some())
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
        }
    }

    let mut user_ids = std::collections::HashSet::new();
    let mut identifiers = std::collections::HashSet::new();
    for user in &configuration.users {
        let identifier = user.identifier.trim().to_lowercase();
        if user.id.is_empty()
            || identifier.is_empty()
            || !valid_bcrypt_hash(&user.password_hash)
            || !user_ids.insert(&user.id)
            || !identifiers.insert(identifier)
        {
            return Err(ConfigurationError::Invalid(
                "users require unique non-empty ids and identifiers plus a bcrypt hash with cost 10 through 16"
                    .to_owned(),
            ));
        }
    }
    for (claim, mapping) in &configuration.claims {
        if matches!(
            claim.as_str(),
            "iss" | "sub" | "aud" | "iat" | "exp" | "nonce"
        ) {
            return Err(ConfigurationError::Invalid(format!(
                "claim {claim} is reserved by OpenID Connect"
            )));
        }
        if claim.is_empty() || mapping.source.is_empty() || mapping.scope.is_empty() {
            return Err(ConfigurationError::Invalid(
                "claim mappings require non-empty claim, source, and scope values".to_owned(),
            ));
        }
    }

    let session = &configuration.authentication.session;
    if configuration.authentication.methods.is_empty()
        || configuration
            .authentication
            .methods
            .iter()
            .any(|method| method != "password")
    {
        return Err(ConfigurationError::Invalid(
            "authentication methods must contain only password".to_owned(),
        ));
    }
    if session.idle_timeout <= 0 || session.absolute_timeout <= 0 || session.max_concurrent <= 0 {
        return Err(ConfigurationError::Invalid(
            "authentication session values must be positive".to_owned(),
        ));
    }
    let rate_limit = &configuration.authentication.rate_limit;
    if rate_limit.attempts <= 0 || rate_limit.window_seconds <= 0 {
        return Err(ConfigurationError::Invalid(
            "authentication rate-limit values must be positive".to_owned(),
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
                        .is_some_and(|key| !key.is_empty())
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
    if default_locale.is_empty()
        || locales.is_empty()
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
        serde_json::Value::String(secret) => !secret.is_empty(),
        serde_json::Value::Object(reference) => {
            reference.len() == 2
                && reference
                    .get("provider")
                    .and_then(serde_json::Value::as_str)
                    == Some("env")
                && reference
                    .get("key")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|key| !key.is_empty())
        }
        _ => false,
    }
}

fn valid_bcrypt_hash(hash: &str) -> bool {
    let bytes = hash.as_bytes();
    if bytes.len() != 60 || !matches!(&bytes[..4], b"$2a$" | b"$2b$" | b"$2y$") || bytes[6] != b'$'
    {
        return false;
    }
    let Ok(cost) = hash[4..6].parse::<u8>() else {
        return false;
    };
    (10..=16).contains(&cost)
        && bytes[7..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/'))
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
                    let sensitive = [
                        "password",
                        "password_hash",
                        "secret",
                        "secret_reference",
                        "private_key",
                        "token",
                    ]
                    .iter()
                    .any(|fragment| normalized.contains(fragment));
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

fn validate_web_url(value: &str, label: &str) -> Result<(), ConfigurationError> {
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

fn default_token_lifetime() -> i64 {
    300
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
            scopes: vec!["openid".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            pkce_required: Some(false),
            nonce_required: None,
            consent_required: None,
            authentication_method: None,
            secret_reference: None,
            branding: None,
        });
        assert!(matches!(
            validate(&configuration),
            Err(ConfigurationError::Invalid(message)) if message.contains("must require PKCE")
        ));
    }
}
