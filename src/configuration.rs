use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};
use thiserror::Error;

const EMBEDDED_ROOT: &str = include_str!("../config/robine_id.json");

#[derive(Clone, Debug, Deserialize, Serialize)]
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Issuer {
    pub id: String,
    pub url: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub token_policy: TokenPolicy,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    #[serde(default)]
    pub pkce_required: Option<bool>,
    #[serde(default)]
    pub nonce_required: Option<bool>,
    #[serde(default)]
    pub consent_required: Option<bool>,
    pub authentication_method: Option<String>,
    pub secret_reference: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
pub struct ClaimMapping {
    pub source: String,
    pub scope: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenPolicy {
    #[serde(default = "default_authorization_code_lifetime")]
    pub authorization_code_lifetime: i64,
    #[serde(default = "default_token_lifetime")]
    pub id_token_lifetime: i64,
    #[serde(default = "default_token_lifetime")]
    pub access_token_lifetime: i64,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            authorization_code_lifetime: default_authorization_code_lifetime(),
            id_token_lifetime: default_token_lifetime(),
            access_token_lifetime: default_token_lifetime(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplicationDocument {
    pub schema_version: u8,
    pub kind: String,
    #[serde(flatten)]
    pub client: Client,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Branding {
    #[serde(default = "default_product_name")]
    pub product_name: String,
    #[serde(default = "default_primary_color")]
    pub primary_color: String,
    pub logo: Option<String>,
    pub favicon: Option<String>,
    pub support_url: Option<String>,
    pub privacy_url: Option<String>,
    pub terms_url: Option<String>,
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

        let root_contents = match fs::read_to_string(&root_path) {
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
        };

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

        let mut fingerprint = Sha256::new();
        fingerprint.update(root_contents.as_bytes());

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
                let document: ApplicationDocument =
                    serde_json::from_str(&contents).map_err(|source| ConfigurationError::Json {
                        path: path.clone(),
                        source,
                    })?;

                if document.schema_version != 1 || document.kind != "oidc_application" {
                    return Err(ConfigurationError::Invalid(format!(
                        "{} must be an oidc_application with schema_version 1",
                        path.display()
                    )));
                }

                fingerprint.update(contents.as_bytes());
                configuration.clients.push(document.client);
            }
        }

        validate(&configuration)?;

        Ok(Self {
            configuration,
            revision: hex::encode(fingerprint.finalize()),
        })
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
}

fn validate(configuration: &RootConfiguration) -> Result<(), ConfigurationError> {
    if configuration.issuers.is_empty() {
        return Err(ConfigurationError::Invalid(
            "at least one issuer is required".to_owned(),
        ));
    }

    for issuer in &configuration.issuers {
        if issuer.id.is_empty() || issuer.url.trim_end_matches('/').is_empty() {
            return Err(ConfigurationError::Invalid(
                "every issuer requires a non-empty id and URL".to_owned(),
            ));
        }
    }

    for client in &configuration.clients {
        if client.id.is_empty() || client.redirect_uris.is_empty() {
            return Err(ConfigurationError::Invalid(
                "every client requires an id and at least one redirect URI".to_owned(),
            ));
        }
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

fn default_product_name() -> String {
    "Robine ID".to_owned()
}

fn default_primary_color() -> String {
    "#176b70".to_owned()
}

fn default_authorization_code_lifetime() -> i64 {
    60
}

fn default_token_lifetime() -> i64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
