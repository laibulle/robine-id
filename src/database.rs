use crate::protocol::{AuthorizationGrant, AuthorizationRequest, authorization_details_subset};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::env;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DatabaseConfigurationError {
    #[error("database environment variable {name} is not valid Unicode")]
    NonUnicode { name: &'static str },
    #[error("DATABASE_URL or PG* database credentials are incomplete")]
    IncompleteCredentials,
    #[error("DATABASE_URL or PG* values do not form a valid PostgreSQL connection URL")]
    InvalidUrl,
    #[error("KEY_ENCRYPTION_SECRET or SECRET_KEY_BASE is required with database credentials")]
    MissingEncryptionSecret,
    #[error("KEY_ENCRYPTION_SECRET or SECRET_KEY_BASE must contain at least 32 bytes")]
    WeakEncryptionSecret,
    #[error("KEY_ENCRYPTION_SECRET_PREVIOUS must contain at least 32 bytes")]
    WeakPreviousEncryptionSecret,
    #[error("KEY_ENCRYPTION_SECRET_PREVIOUS must differ from the current encryption secret")]
    MatchingEncryptionSecrets,
    #[error("{name} must be an integer between {minimum} and {maximum}")]
    InvalidInteger {
        name: &'static str,
        minimum: u64,
        maximum: u64,
    },
}

#[derive(Default)]
struct DatabaseEnvironment {
    database_url: Option<String>,
    pg_host: Option<String>,
    pg_port: Option<String>,
    pg_database: Option<String>,
    pg_user: Option<String>,
    pg_password: Option<String>,
    postgres_password: Option<String>,
    key_encryption_secret: Option<String>,
    previous_key_encryption_secret: Option<String>,
    secret_key_base: Option<String>,
    maximum_connections: Option<String>,
    acquire_timeout_ms: Option<String>,
    statement_timeout_ms: Option<String>,
    vercel: bool,
}

impl DatabaseEnvironment {
    fn read() -> Result<Self, DatabaseConfigurationError> {
        Ok(Self {
            database_url: environment_value("DATABASE_URL")?,
            pg_host: environment_value("PGHOST")?,
            pg_port: environment_value("PGPORT")?,
            pg_database: environment_value("PGDATABASE")?,
            pg_user: environment_value("PGUSER")?,
            pg_password: environment_value("PGPASSWORD")?,
            postgres_password: environment_value("POSTGRES_PASSWORD")?,
            key_encryption_secret: environment_value("KEY_ENCRYPTION_SECRET")?,
            previous_key_encryption_secret: environment_value("KEY_ENCRYPTION_SECRET_PREVIOUS")?,
            secret_key_base: environment_value("SECRET_KEY_BASE")?,
            maximum_connections: environment_value("DATABASE_MAX_CONNECTIONS")?,
            acquire_timeout_ms: environment_value("DATABASE_ACQUIRE_TIMEOUT_MS")?,
            statement_timeout_ms: environment_value("DATABASE_STATEMENT_TIMEOUT_MS")?,
            vercel: env::var_os("VERCEL").is_some(),
        })
    }

    fn build(self) -> Result<Option<Database>, DatabaseConfigurationError> {
        let component_credentials_present = self.pg_host.is_some()
            || self.pg_port.is_some()
            || self.pg_database.is_some()
            || self.pg_user.is_some()
            || self.pg_password.is_some()
            || self.postgres_password.is_some();
        let operational_settings_present = self.maximum_connections.is_some()
            || self.acquire_timeout_ms.is_some()
            || self.statement_timeout_ms.is_some()
            || self.previous_key_encryption_secret.is_some();
        let secret = self.key_encryption_secret.or(self.secret_key_base);
        let url = match self.database_url {
            Some(url) => Some(url),
            None if component_credentials_present => {
                let host = self
                    .pg_host
                    .ok_or(DatabaseConfigurationError::IncompleteCredentials)?;
                let password = self
                    .pg_password
                    .or(self.postgres_password)
                    .ok_or(DatabaseConfigurationError::IncompleteCredentials)?;
                Some(
                    database_url_from_components(
                        &host,
                        self.pg_port.as_deref().unwrap_or("5432"),
                        self.pg_database.as_deref().unwrap_or("robine_id"),
                        self.pg_user.as_deref().unwrap_or("robine_id"),
                        &password,
                    )
                    .ok_or(DatabaseConfigurationError::InvalidUrl)?,
                )
            }
            None => None,
        };
        let Some(url) = url else {
            if secret.is_some() || operational_settings_present {
                return Err(DatabaseConfigurationError::IncompleteCredentials);
            }
            return Ok(None);
        };
        let secret = secret.ok_or(DatabaseConfigurationError::MissingEncryptionSecret)?;
        if secret.len() < 32 {
            return Err(DatabaseConfigurationError::WeakEncryptionSecret);
        }
        if self
            .previous_key_encryption_secret
            .as_deref()
            .is_some_and(|previous| previous.len() < 32)
        {
            return Err(DatabaseConfigurationError::WeakPreviousEncryptionSecret);
        }
        if self.previous_key_encryption_secret.as_deref() == Some(secret.as_str()) {
            return Err(DatabaseConfigurationError::MatchingEncryptionSecrets);
        }
        let default_connections = if self.vercel { 2 } else { 5 };
        let default_timeout_ms = if self.vercel { 2_000 } else { 5_000 };
        let maximum_connections = bounded_integer(
            "DATABASE_MAX_CONNECTIONS",
            self.maximum_connections.as_deref(),
            1,
            50,
        )?
        .unwrap_or(default_connections);
        let acquire_timeout_ms = bounded_integer(
            "DATABASE_ACQUIRE_TIMEOUT_MS",
            self.acquire_timeout_ms.as_deref(),
            100,
            30_000,
        )?
        .unwrap_or(default_timeout_ms);
        let statement_timeout_ms = bounded_integer(
            "DATABASE_STATEMENT_TIMEOUT_MS",
            self.statement_timeout_ms.as_deref(),
            100,
            30_000,
        )?
        .unwrap_or(default_timeout_ms);
        Database::configured(
            url,
            secret,
            self.previous_key_encryption_secret,
            maximum_connections as u32,
            acquire_timeout_ms,
            statement_timeout_ms,
        )
        .map(Some)
    }
}

fn environment_value(name: &'static str) -> Result<Option<String>, DatabaseConfigurationError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(DatabaseConfigurationError::NonUnicode { name }),
    }
}

fn bounded_integer(
    name: &'static str,
    value: Option<&str>,
    minimum: u64,
    maximum: u64,
) -> Result<Option<u64>, DatabaseConfigurationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    value
        .parse::<u64>()
        .ok()
        .filter(|value| (minimum..=maximum).contains(value))
        .map(Some)
        .ok_or(DatabaseConfigurationError::InvalidInteger {
            name,
            minimum,
            maximum,
        })
}

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
    key_encryption_key: [u8; 32],
    previous_key_encryption_key: Option<[u8; 32]>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct AccessGrant {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub grant_type: String,
    pub resource: Option<String>,
    pub dpop_jkt: Option<String>,
    pub auth_time: Option<i64>,
    pub mfa_verified: bool,
    pub claims: Value,
    pub authorization_details: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct IntrospectionGrant {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub grant_type: String,
    pub resource: Option<String>,
    pub dpop_jkt: Option<String>,
    pub auth_time: Option<i64>,
    pub mfa_verified: bool,
    pub authorization_details: Value,
    pub expires_at: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct DeviceAuthorization {
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub resource: Option<String>,
    pub authorization_details: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct DeviceGrant {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub resource: Option<String>,
    pub auth_time: Option<i64>,
    pub mfa_verified: bool,
    pub claims: Value,
    pub authorization_details: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub enum DevicePoll {
    Pending,
    SlowDown,
    Approved(DeviceGrant),
    Denied,
    Expired,
    Invalid,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct RefreshGrant {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub resource: Option<String>,
    pub dpop_jkt: Option<String>,
    pub auth_time: Option<i64>,
    pub mfa_verified: bool,
    pub claims: Value,
    pub authorization_details: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub enum RefreshRotation {
    Rotated {
        token: String,
        grant: Box<RefreshGrant>,
    },
    Invalid,
    InvalidScope,
    InvalidTarget,
    InvalidAuthorizationDetails,
    InvalidDpopProof,
    Replayed,
}

#[derive(Debug, sqlx::FromRow)]
struct StoredRefreshToken {
    family_id: Vec<u8>,
    issuer: String,
    subject: String,
    client_id: String,
    scopes: Vec<String>,
    resource: Option<String>,
    dpop_jkt: Option<String>,
    auth_time: Option<i64>,
    mfa_verified: bool,
    claims: Value,
    authorization_details: Value,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct PendingAuthorization {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub response_mode: Option<String>,
    pub resource: Option<String>,
    pub dpop_jkt: Option<String>,
    pub auth_time: Option<i64>,
    pub mfa_verified: bool,
    pub claims: Value,
    pub authorization_details: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct ValidatedSession {
    pub subject: String,
    pub authenticated_at: DateTime<Utc>,
    pub mfa_verified: bool,
}

#[derive(Debug, sqlx::FromRow)]
pub struct TotpChallenge {
    pub subject: String,
    pub purpose: String,
    pub payload: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct SigningKey {
    pub kid: String,
    pub private_key_pem: String,
    pub modulus: String,
    pub exponent: String,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct PublicSigningKey {
    pub kid: String,
    pub modulus: String,
    pub exponent: String,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct StoredSigningKey {
    kid: String,
    private_key_ciphertext: Vec<u8>,
    private_key_nonce: Vec<u8>,
    modulus: String,
    exponent: String,
}

#[derive(Debug, sqlx::FromRow)]
struct EncryptedSigningKey {
    issuer: String,
    kid: String,
    private_key_ciphertext: Vec<u8>,
    private_key_nonce: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReencryptedSigningKeys {
    pub active: u64,
    pub retained: u64,
}

impl Database {
    pub fn from_env() -> Result<Option<Self>, DatabaseConfigurationError> {
        DatabaseEnvironment::read()?.build()
    }

    fn configured(
        url: String,
        secret: String,
        previous_secret: Option<String>,
        maximum_connections: u32,
        acquire_timeout_ms: u64,
        statement_timeout_ms: u64,
    ) -> Result<Self, DatabaseConfigurationError> {
        let key_encryption_key: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        let previous_key_encryption_key =
            previous_secret.map(|secret| <[u8; 32]>::from(Sha256::digest(secret.as_bytes())));
        let statement_timeout = format!("{statement_timeout_ms}ms");
        let pool = PgPoolOptions::new()
            .max_connections(maximum_connections)
            .acquire_timeout(std::time::Duration::from_millis(acquire_timeout_ms))
            .after_connect(move |connection, _metadata| {
                let statement_timeout = statement_timeout.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                        .bind(statement_timeout)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_lazy(&url)
            .map_err(|_| DatabaseConfigurationError::InvalidUrl)?;
        Ok(Self {
            pool,
            key_encryption_key,
            previous_key_encryption_key,
        })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        // Embed the complete migration set in both conventional and serverless binaries.
        sqlx::migrate!().run(&self.pool).await?;
        self.cleanup_expired_state().await
    }

    pub async fn cleanup_expired_state(&self) -> Result<(), sqlx::Error> {
        for statement in [
            "DELETE FROM authorization_codes WHERE expires_at <= now()",
            "DELETE FROM access_tokens WHERE expires_at <= now()",
            "DELETE FROM refresh_tokens WHERE expires_at <= now() - interval '7 days'",
            "DELETE FROM pending_authorizations WHERE expires_at <= now()",
            "DELETE FROM pushed_authorizations WHERE expires_at <= now()",
            "DELETE FROM browser_authorizations WHERE expires_at <= now()",
            "DELETE FROM totp_challenges WHERE expires_at <= now()",
            "DELETE FROM totp_replay_counters WHERE updated_at <= now() - interval '1 day'",
            "DELETE FROM device_authorizations WHERE expires_at <= now() - interval '1 day'",
            "DELETE FROM logout_transactions WHERE expires_at <= now()",
            "DELETE FROM authenticated_sessions WHERE absolute_expires_at <= now() - interval '7 days' OR revoked_at <= now() - interval '7 days'",
            "DELETE FROM authentication_rate_limits WHERE window_started_at <= now() - interval '30 days'",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn healthy(&self) -> bool {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    pub async fn register_client_assertion(
        &self,
        issuer: &str,
        client_id: &str,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM oauth_client_assertions WHERE expires_at <= now()")
            .execute(&mut *transaction)
            .await?;
        let result = sqlx::query(
            "INSERT INTO oauth_client_assertions (issuer, client_id, jti_hash, expires_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING",
        )
        .bind(issuer)
        .bind(client_id)
        .bind(digest(jti))
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn register_request_object(
        &self,
        issuer: &str,
        client_id: &str,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM oauth_request_objects WHERE expires_at <= now()")
            .execute(&mut *transaction)
            .await?;
        let result = sqlx::query(
            "INSERT INTO oauth_request_objects (issuer, client_id, jti_hash, expires_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING",
        )
        .bind(issuer)
        .bind(client_id)
        .bind(digest(jti))
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn register_dpop_proof(
        &self,
        jkt: &str,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM oauth_dpop_proofs WHERE expires_at <= now()")
            .execute(&mut *transaction)
            .await?;
        let result = sqlx::query(
            "INSERT INTO oauth_dpop_proofs (jkt, jti_hash, expires_at)
             VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
        )
        .bind(jkt)
        .bind(digest(jti))
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn validate_or_issue_dpop_nonce(
        &self,
        issuer: &str,
        context: &str,
        jkt: &str,
        submitted_nonce: Option<&str>,
        lifetime_seconds: i64,
    ) -> Result<Option<String>, sqlx::Error> {
        if !(30..=3_600).contains(&lifetime_seconds)
            || !matches!(context, "authorization_server" | "userinfo")
        {
            return Err(sqlx::Error::Protocol(
                "invalid DPoP nonce policy".to_owned(),
            ));
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(
               hashtextextended(concat_ws(E'\\x1f', $1, $2, $3), 0)
             )",
        )
        .bind(issuer)
        .bind(context)
        .bind(jkt)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM oauth_dpop_nonces WHERE expires_at <= now()")
            .execute(&mut *transaction)
            .await?;
        let valid = match submitted_nonce {
            Some(nonce) => {
                sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(
                       SELECT 1 FROM oauth_dpop_nonces
                       WHERE nonce_hash = $1 AND issuer = $2 AND context = $3 AND jkt = $4
                         AND expires_at > now()
                     )",
                )
                .bind(digest(nonce))
                .bind(issuer)
                .bind(context)
                .bind(jkt)
                .fetch_one(&mut *transaction)
                .await?
            }
            None => false,
        };
        if valid {
            transaction.commit().await?;
            return Ok(None);
        }

        sqlx::query(
            "DELETE FROM oauth_dpop_nonces
             WHERE nonce_hash IN (
               SELECT nonce_hash FROM oauth_dpop_nonces
               WHERE issuer = $1 AND context = $2 AND jkt = $3 AND expires_at > now()
               ORDER BY expires_at DESC, nonce_hash
               OFFSET 3
             )",
        )
        .bind(issuer)
        .bind(context)
        .bind(jkt)
        .execute(&mut *transaction)
        .await?;
        let nonce = random_token();
        sqlx::query(
            "INSERT INTO oauth_dpop_nonces
             (nonce_hash, issuer, context, jkt, expires_at)
             VALUES ($1, $2, $3, $4, now() + ($5 * interval '1 second'))",
        )
        .bind(digest(&nonce))
        .bind(issuer)
        .bind(context)
        .bind(jkt)
        .bind(lifetime_seconds)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Some(nonce))
    }

    pub async fn statement_timeout_milliseconds(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT (EXTRACT(EPOCH FROM current_setting('statement_timeout')::interval) * 1000)::BIGINT",
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn issue_authorization_code(
        &self,
        grant: &AuthorizationGrant,
    ) -> Result<String, sqlx::Error> {
        let code = random_token();
        let hash = digest(&code);
        sqlx::query(
            "INSERT INTO authorization_codes
             (code_hash, issuer, subject, client_id, redirect_uri, scopes, nonce, code_challenge,
              response_mode, resource, dpop_jkt, auth_time, mfa_verified, claims,
              authorization_details, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
        )
        .bind(hash)
        .bind(&grant.issuer)
        .bind(&grant.subject)
        .bind(&grant.client_id)
        .bind(&grant.redirect_uri)
        .bind(&grant.scopes)
        .bind(&grant.nonce)
        .bind(&grant.code_challenge)
        .bind(&grant.response_mode)
        .bind(&grant.resource)
        .bind(&grant.dpop_jkt)
        .bind(grant.auth_time)
        .bind(grant.mfa_verified)
        .bind(&grant.claims)
        .bind(&grant.authorization_details)
        .bind(grant.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(code)
    }

    pub async fn issue_pushed_authorization(
        &self,
        issuer: &str,
        client_id: &str,
        request: &AuthorizationRequest,
        lifetime_seconds: i64,
    ) -> Result<String, sqlx::Error> {
        if !(10..=600).contains(&lifetime_seconds) {
            return Err(sqlx::Error::Protocol(
                "pushed authorization lifetime must contain 10 to 600 seconds".to_owned(),
            ));
        }
        let token = random_token();
        let request_uri = format!("urn:ietf:params:oauth:request_uri:{token}");
        let request =
            serde_json::to_value(request).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        sqlx::query(
            "INSERT INTO pushed_authorizations
             (request_hash, issuer, client_id, request, expires_at)
             VALUES ($1, $2, $3, $4, now() + ($5 * interval '1 second'))",
        )
        .bind(digest(&request_uri))
        .bind(issuer)
        .bind(client_id)
        .bind(request)
        .bind(lifetime_seconds)
        .execute(&self.pool)
        .await?;
        Ok(request_uri)
    }

    pub async fn issue_browser_authorization(
        &self,
        issuer: &str,
        request: &AuthorizationRequest,
        lifetime_seconds: i64,
    ) -> Result<String, sqlx::Error> {
        if !(60..=3_600).contains(&lifetime_seconds) {
            return Err(sqlx::Error::Protocol(
                "browser authorization lifetime must contain 60 to 3600 seconds".to_owned(),
            ));
        }
        let transaction = random_token();
        let request =
            serde_json::to_value(request).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        sqlx::query(
            "INSERT INTO browser_authorizations
             (transaction_hash, issuer, request, expires_at)
             VALUES ($1, $2, $3, now() + ($4 * interval '1 second'))",
        )
        .bind(digest(&transaction))
        .bind(issuer)
        .bind(request)
        .bind(lifetime_seconds)
        .execute(&self.pool)
        .await?;
        Ok(transaction)
    }

    pub async fn consume_browser_authorization(
        &self,
        transaction: &str,
        issuer: &str,
    ) -> Result<Option<AuthorizationRequest>, sqlx::Error> {
        if !valid_opaque_token(transaction) {
            return Ok(None);
        }
        let request = sqlx::query_scalar::<_, Value>(
            "DELETE FROM browser_authorizations
             WHERE transaction_hash = $1 AND issuer = $2 AND expires_at > now()
             RETURNING request",
        )
        .bind(digest(transaction))
        .bind(issuer)
        .fetch_optional(&self.pool)
        .await?;
        request
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))
    }

    pub async fn issue_totp_challenge(
        &self,
        issuer: &str,
        subject: &str,
        purpose: &str,
        payload: &Value,
        lifetime_seconds: i64,
    ) -> Result<String, sqlx::Error> {
        if !matches!(purpose, "authorization" | "device")
            || !(60..=3_600).contains(&lifetime_seconds)
            || !payload.is_object()
        {
            return Err(sqlx::Error::Protocol(
                "invalid TOTP challenge policy".to_owned(),
            ));
        }
        let transaction = random_token();
        sqlx::query(
            "INSERT INTO totp_challenges
             (transaction_hash, issuer, subject, purpose, payload, expires_at)
             VALUES ($1, $2, $3, $4, $5, now() + ($6 * interval '1 second'))",
        )
        .bind(digest(&transaction))
        .bind(issuer)
        .bind(subject)
        .bind(purpose)
        .bind(payload)
        .bind(lifetime_seconds)
        .execute(&self.pool)
        .await?;
        Ok(transaction)
    }

    pub async fn totp_challenge(
        &self,
        transaction: &str,
        issuer: &str,
        purpose: &str,
    ) -> Result<Option<TotpChallenge>, sqlx::Error> {
        if !valid_opaque_token(transaction) {
            return Ok(None);
        }
        sqlx::query_as(
            "SELECT subject, purpose, payload, expires_at
             FROM totp_challenges
             WHERE transaction_hash = $1 AND issuer = $2 AND purpose = $3
               AND expires_at > now()",
        )
        .bind(digest(transaction))
        .bind(issuer)
        .bind(purpose)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn consume_totp_challenge(
        &self,
        transaction: &str,
        issuer: &str,
        subject: &str,
        purpose: &str,
        counter: i64,
    ) -> Result<bool, sqlx::Error> {
        if !valid_opaque_token(transaction) || counter < 0 {
            return Ok(false);
        }
        let mut database_transaction = self.pool.begin().await?;
        let consumed = sqlx::query_scalar::<_, String>(
            "DELETE FROM totp_challenges
             WHERE transaction_hash = $1 AND issuer = $2 AND subject = $3 AND purpose = $4
               AND expires_at > now()
             RETURNING subject",
        )
        .bind(digest(transaction))
        .bind(issuer)
        .bind(subject)
        .bind(purpose)
        .fetch_optional(&mut *database_transaction)
        .await?
        .is_some();
        if !consumed {
            database_transaction.commit().await?;
            return Ok(false);
        }
        let registered = sqlx::query_scalar::<_, i64>(
            "INSERT INTO totp_replay_counters (issuer, subject, last_counter)
             VALUES ($1, $2, $3)
             ON CONFLICT (issuer, subject) DO UPDATE
               SET last_counter = EXCLUDED.last_counter, updated_at = now()
               WHERE totp_replay_counters.last_counter < EXCLUDED.last_counter
             RETURNING last_counter",
        )
        .bind(issuer)
        .bind(subject)
        .bind(counter)
        .fetch_optional(&mut *database_transaction)
        .await?
        .is_some();
        database_transaction.commit().await?;
        Ok(registered)
    }

    pub async fn consume_pushed_authorization(
        &self,
        request_uri: &str,
        issuer: &str,
        client_id: &str,
    ) -> Result<Option<AuthorizationRequest>, sqlx::Error> {
        let request = sqlx::query_scalar::<_, Value>(
            "DELETE FROM pushed_authorizations
             WHERE request_hash = $1 AND issuer = $2 AND client_id = $3 AND expires_at > now()
             RETURNING request",
        )
        .bind(digest(request_uri))
        .bind(issuer)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        request
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))
    }

    pub async fn consume_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationGrant>, sqlx::Error> {
        sqlx::query_as::<_, AuthorizationGrant>(
            "DELETE FROM authorization_codes WHERE code_hash = $1
             RETURNING issuer, subject, client_id, redirect_uri, scopes, nonce,
                       code_challenge, response_mode, resource, dpop_jkt, auth_time, mfa_verified,
                       claims, authorization_details, expires_at",
        )
        .bind(digest(code))
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn issue_device_authorization(
        &self,
        issuer: &str,
        client_id: &str,
        scopes: &[String],
        resource: Option<&str>,
        authorization_details: &Value,
        lifetime_seconds: i64,
        poll_interval_seconds: i32,
    ) -> Result<(String, String), sqlx::Error> {
        if !(300..=1_800).contains(&lifetime_seconds)
            || !(5..=60).contains(&poll_interval_seconds)
            || scopes.is_empty()
            || scopes.len() > 256
        {
            return Err(sqlx::Error::Protocol(
                "invalid device authorization policy".to_owned(),
            ));
        }
        for _ in 0..5 {
            let device_code = random_token();
            let user_code = random_user_code();
            let result = sqlx::query(
                "INSERT INTO device_authorizations
                 (device_code_hash, user_code_hash, issuer, client_id, scopes, resource,
                  authorization_details, poll_interval, last_polled_at, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now() + ($9 * interval '1 second'))
                 ON CONFLICT DO NOTHING",
            )
            .bind(digest(&device_code))
            .bind(digest(&user_code))
            .bind(issuer)
            .bind(client_id)
            .bind(scopes)
            .bind(resource)
            .bind(authorization_details)
            .bind(poll_interval_seconds)
            .bind(lifetime_seconds)
            .execute(&self.pool)
            .await?;
            if result.rows_affected() == 1 {
                return Ok((device_code, format_user_code(&user_code)));
            }
        }
        Err(sqlx::Error::Protocol(
            "could not allocate a unique device authorization".to_owned(),
        ))
    }

    pub async fn begin_device_verification(
        &self,
        user_code: &str,
        issuer: &str,
    ) -> Result<Option<(String, DeviceAuthorization)>, sqlx::Error> {
        let transaction = random_token();
        let authorization = sqlx::query_as::<_, DeviceAuthorization>(
            "UPDATE device_authorizations
             SET verification_hash = $1
             WHERE user_code_hash = $2 AND issuer = $3 AND status = 'pending'
               AND expires_at > now()
             RETURNING issuer, client_id, scopes, resource, authorization_details, expires_at",
        )
        .bind(digest(&transaction))
        .bind(digest(user_code))
        .bind(issuer)
        .fetch_optional(&self.pool)
        .await?;
        Ok(authorization.map(|authorization| (transaction, authorization)))
    }

    pub async fn device_verification(
        &self,
        transaction: &str,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorization>, sqlx::Error> {
        sqlx::query_as::<_, DeviceAuthorization>(
            "SELECT issuer, client_id, scopes, resource, authorization_details, expires_at
             FROM device_authorizations
             WHERE verification_hash = $1 AND user_code_hash = $2
               AND status = 'pending' AND expires_at > now()",
        )
        .bind(digest(transaction))
        .bind(digest(user_code))
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn device_verification_by_transaction(
        &self,
        transaction: &str,
    ) -> Result<Option<DeviceAuthorization>, sqlx::Error> {
        if !valid_opaque_token(transaction) {
            return Ok(None);
        }
        sqlx::query_as::<_, DeviceAuthorization>(
            "SELECT issuer, client_id, scopes, resource, authorization_details, expires_at
             FROM device_authorizations
             WHERE verification_hash = $1 AND status = 'pending' AND expires_at > now()",
        )
        .bind(digest(transaction))
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn decide_device_authorization(
        &self,
        transaction: &str,
        subject: &str,
        claims: &Value,
        auth_time: i64,
        approved: bool,
        mfa_verified: bool,
    ) -> Result<bool, sqlx::Error> {
        let status = if approved { "approved" } else { "denied" };
        let empty_claims = serde_json::json!({});
        let result = sqlx::query(
            "UPDATE device_authorizations
             SET status = $1, subject = $2, claims = $3, auth_time = $4, mfa_verified = $5,
                 decision_at = now(), verification_hash = NULL
             WHERE verification_hash = $6 AND status = 'pending' AND expires_at > now()",
        )
        .bind(status)
        .bind(approved.then_some(subject))
        .bind(if approved { claims } else { &empty_claims })
        .bind(approved.then_some(auth_time))
        .bind(approved && mfa_verified)
        .bind(digest(transaction))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn poll_device_authorization(
        &self,
        device_code: &str,
        issuer: &str,
        client_id: &str,
    ) -> Result<DevicePoll, sqlx::Error> {
        #[derive(sqlx::FromRow)]
        struct StoredDeviceAuthorization {
            status: String,
            issuer: String,
            subject: Option<String>,
            client_id: String,
            scopes: Vec<String>,
            resource: Option<String>,
            auth_time: Option<i64>,
            mfa_verified: bool,
            claims: Value,
            authorization_details: Value,
            expires_at: DateTime<Utc>,
            poll_interval: i32,
            last_polled_at: Option<DateTime<Utc>>,
        }

        let code_hash = digest(device_code);
        let mut transaction = self.pool.begin().await?;
        let stored = sqlx::query_as::<_, StoredDeviceAuthorization>(
            "SELECT status, issuer, subject, client_id, scopes, resource, auth_time, mfa_verified, claims,
                    authorization_details,
                    expires_at, poll_interval, last_polled_at
             FROM device_authorizations
             WHERE device_code_hash = $1 AND issuer = $2 AND client_id = $3
             FOR UPDATE",
        )
        .bind(&code_hash)
        .bind(issuer)
        .bind(client_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(stored) = stored else {
            transaction.commit().await?;
            return Ok(DevicePoll::Invalid);
        };
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
            .fetch_one(&mut *transaction)
            .await?;
        if stored.expires_at <= now {
            sqlx::query("DELETE FROM device_authorizations WHERE device_code_hash = $1")
                .bind(&code_hash)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            return Ok(DevicePoll::Expired);
        }
        if stored.status == "denied" {
            sqlx::query("DELETE FROM device_authorizations WHERE device_code_hash = $1")
                .bind(&code_hash)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            return Ok(DevicePoll::Denied);
        }
        if stored.status == "approved" {
            sqlx::query("DELETE FROM device_authorizations WHERE device_code_hash = $1")
                .bind(&code_hash)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            let (Some(subject), Some(auth_time)) = (stored.subject, stored.auth_time) else {
                return Ok(DevicePoll::Invalid);
            };
            return Ok(DevicePoll::Approved(DeviceGrant {
                issuer: stored.issuer,
                subject,
                client_id: stored.client_id,
                scopes: stored.scopes,
                resource: stored.resource,
                auth_time: Some(auth_time),
                mfa_verified: stored.mfa_verified,
                claims: stored.claims,
                authorization_details: stored.authorization_details,
                expires_at: stored.expires_at,
            }));
        }

        let too_soon = stored.last_polled_at.is_some_and(|last_polled_at| {
            now < last_polled_at + chrono::Duration::seconds(i64::from(stored.poll_interval))
        });
        let next_interval = if too_soon {
            stored.poll_interval.saturating_add(5).min(300)
        } else {
            stored.poll_interval
        };
        sqlx::query(
            "UPDATE device_authorizations
             SET last_polled_at = $1, poll_interval = $2
             WHERE device_code_hash = $3",
        )
        .bind(now)
        .bind(next_interval)
        .bind(&code_hash)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(if too_soon {
            DevicePoll::SlowDown
        } else {
            DevicePoll::Pending
        })
    }

    pub async fn issue_access_token(&self, grant: &AccessGrant) -> Result<String, sqlx::Error> {
        let token = random_token();
        self.store_access_token(&token, grant).await?;
        Ok(token)
    }

    pub async fn store_access_token(
        &self,
        token: &str,
        grant: &AccessGrant,
    ) -> Result<(), sqlx::Error> {
        if token.is_empty() || token.len() > 12 * 1024 {
            return Err(sqlx::Error::Protocol(
                "access token exceeds the storage bound".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO access_tokens
             (token_hash, issuer, subject, client_id, scopes, grant_type, resource, dpop_jkt,
              auth_time, mfa_verified, claims, authorization_details, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(digest(token))
        .bind(&grant.issuer)
        .bind(&grant.subject)
        .bind(&grant.client_id)
        .bind(&grant.scopes)
        .bind(&grant.grant_type)
        .bind(&grant.resource)
        .bind(&grant.dpop_jkt)
        .bind(grant.auth_time)
        .bind(grant.mfa_verified)
        .bind(&grant.claims)
        .bind(&grant.authorization_details)
        .bind(grant.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn access_grant(&self, token: &str) -> Result<Option<AccessGrant>, sqlx::Error> {
        sqlx::query_as::<_, AccessGrant>(
            "SELECT issuer, subject, client_id, scopes, grant_type, resource, dpop_jkt,
                    auth_time, mfa_verified, claims, authorization_details, expires_at
             FROM access_tokens WHERE token_hash = $1 AND expires_at > now()",
        )
        .bind(digest(token))
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn introspection_grant(
        &self,
        token: &str,
        issuer: &str,
    ) -> Result<Option<IntrospectionGrant>, sqlx::Error> {
        sqlx::query_as::<_, IntrospectionGrant>(
            "SELECT issuer, subject, client_id, scopes, grant_type, resource, dpop_jkt,
                    auth_time, mfa_verified, authorization_details, expires_at, created_at AS issued_at
             FROM access_tokens
             WHERE token_hash = $1 AND issuer = $2 AND expires_at > now()",
        )
        .bind(digest(token))
        .bind(issuer)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn revoke_access_token(
        &self,
        token: &str,
        issuer: &str,
        client_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM access_tokens
             WHERE token_hash = $1 AND issuer = $2 AND client_id = $3",
        )
        .bind(digest(token))
        .bind(issuer)
        .bind(client_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn issue_refresh_token(&self, grant: &RefreshGrant) -> Result<String, sqlx::Error> {
        let token = random_token();
        let family_id = digest(&random_token());
        self.insert_refresh_token(&token, &family_id, grant, &self.pool)
            .await?;
        Ok(token)
    }

    pub async fn rotate_refresh_token(
        &self,
        token: &str,
        issuer: &str,
        client_id: &str,
        requested_scopes: Option<&[String]>,
        requested_resource: Option<&str>,
        requested_authorization_details: Option<&Value>,
        requested_dpop_jkt: Option<&str>,
    ) -> Result<RefreshRotation, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let stored = sqlx::query_as::<_, StoredRefreshToken>(
            "SELECT family_id, issuer, subject, client_id, scopes, resource, dpop_jkt, auth_time,
                    mfa_verified, claims, authorization_details, expires_at,
                    consumed_at, revoked_at
             FROM refresh_tokens
             WHERE token_hash = $1 AND issuer = $2 AND client_id = $3
             FOR UPDATE",
        )
        .bind(digest(token))
        .bind(issuer)
        .bind(client_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(stored) = stored else {
            transaction.commit().await?;
            return Ok(RefreshRotation::Invalid);
        };
        if stored
            .dpop_jkt
            .as_deref()
            .is_some_and(|expected| Some(expected) != requested_dpop_jkt)
        {
            transaction.commit().await?;
            return Ok(RefreshRotation::InvalidDpopProof);
        }
        if stored.consumed_at.is_some() {
            sqlx::query(
                "UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now())
                 WHERE family_id = $1",
            )
            .bind(&stored.family_id)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(RefreshRotation::Replayed);
        }
        if stored.revoked_at.is_some() || stored.expires_at <= Utc::now() {
            transaction.commit().await?;
            return Ok(RefreshRotation::Invalid);
        }
        if requested_resource.is_some() && requested_resource != stored.resource.as_deref() {
            transaction.commit().await?;
            return Ok(RefreshRotation::InvalidTarget);
        }
        let scopes = match requested_scopes {
            Some(scopes)
                if scopes.is_empty()
                    || scopes.iter().any(|scope| !stored.scopes.contains(scope)) =>
            {
                transaction.commit().await?;
                return Ok(RefreshRotation::InvalidScope);
            }
            Some(scopes) => scopes.to_vec(),
            None => stored.scopes,
        };
        let authorization_details = match requested_authorization_details {
            Some(requested)
                if !authorization_details_subset(requested, &stored.authorization_details) =>
            {
                transaction.commit().await?;
                return Ok(RefreshRotation::InvalidAuthorizationDetails);
            }
            Some(requested) => requested.clone(),
            None => stored.authorization_details,
        };

        sqlx::query("UPDATE refresh_tokens SET consumed_at = now() WHERE token_hash = $1")
            .bind(digest(token))
            .execute(&mut *transaction)
            .await?;
        let rotated = random_token();
        let grant = RefreshGrant {
            issuer: stored.issuer,
            subject: stored.subject,
            client_id: stored.client_id,
            scopes,
            resource: stored.resource,
            dpop_jkt: stored
                .dpop_jkt
                .or_else(|| requested_dpop_jkt.map(str::to_owned)),
            auth_time: stored.auth_time,
            mfa_verified: stored.mfa_verified,
            claims: stored.claims,
            authorization_details,
            expires_at: stored.expires_at,
        };
        self.insert_refresh_token(&rotated, &stored.family_id, &grant, &mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(RefreshRotation::Rotated {
            token: rotated,
            grant: Box::new(grant),
        })
    }

    pub async fn revoke_refresh_token(
        &self,
        token: &str,
        issuer: &str,
        client_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now())
             WHERE family_id = (
               SELECT family_id FROM refresh_tokens
               WHERE token_hash = $1 AND issuer = $2 AND client_id = $3
             )",
        )
        .bind(digest(token))
        .bind(issuer)
        .bind(client_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn insert_refresh_token<'e, E>(
        &self,
        token: &str,
        family_id: &[u8],
        grant: &RefreshGrant,
        executor: E,
    ) -> Result<(), sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query(
            "INSERT INTO refresh_tokens
             (token_hash, family_id, issuer, subject, client_id, scopes, resource, dpop_jkt, auth_time,
              mfa_verified, claims, authorization_details, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(digest(token))
        .bind(family_id)
        .bind(&grant.issuer)
        .bind(&grant.subject)
        .bind(&grant.client_id)
        .bind(&grant.scopes)
        .bind(&grant.resource)
        .bind(&grant.dpop_jkt)
        .bind(grant.auth_time)
        .bind(grant.mfa_verified)
        .bind(&grant.claims)
        .bind(&grant.authorization_details)
        .bind(grant.expires_at)
        .execute(executor)
        .await?;
        Ok(())
    }

    pub async fn allow_authentication_attempt(
        &self,
        key: &str,
        limit: i32,
        window_seconds: i32,
    ) -> Result<bool, sqlx::Error> {
        self.allow_authentication_attempts(&[key.to_owned()], limit, window_seconds)
            .await
    }

    pub async fn allow_authentication_attempts(
        &self,
        keys: &[String],
        limit: i32,
        window_seconds: i32,
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let mut allowed = true;
        for key in keys {
            let attempts: i32 = sqlx::query_scalar(
                "INSERT INTO authentication_rate_limits (key_hash, attempts, window_started_at)
                 VALUES ($1, 1, now())
                 ON CONFLICT (key_hash) DO UPDATE SET
                   attempts = CASE
                     WHEN authentication_rate_limits.window_started_at <= now() - ($2 * interval '1 second') THEN 1
                     ELSE authentication_rate_limits.attempts + 1
                   END,
                   window_started_at = CASE
                     WHEN authentication_rate_limits.window_started_at <= now() - ($2 * interval '1 second') THEN now()
                     ELSE authentication_rate_limits.window_started_at
                   END
                 RETURNING attempts",
            )
            .bind(self.private_digest(key))
            .bind(window_seconds)
            .fetch_one(&mut *transaction)
            .await?;
            allowed &= attempts <= limit;
        }
        transaction.commit().await?;
        Ok(allowed)
    }

    pub async fn start_session(
        &self,
        subject: &str,
        maximum: i64,
        absolute_timeout_seconds: i64,
        mfa_verified: bool,
    ) -> Result<String, sqlx::Error> {
        let session = random_token();
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(subject)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "INSERT INTO authenticated_sessions
             (session_hash, subject, absolute_expires_at, mfa_verified)
             VALUES ($1, $2, now() + ($3 * interval '1 second'), $4)",
        )
        .bind(digest(&session))
        .bind(subject)
        .bind(absolute_timeout_seconds)
        .bind(mfa_verified)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "WITH excess AS (
               SELECT session_hash FROM authenticated_sessions
               WHERE subject = $1 AND revoked_at IS NULL
               ORDER BY created_at DESC OFFSET $2
             )
             UPDATE authenticated_sessions SET revoked_at = now()
             WHERE session_hash IN (SELECT session_hash FROM excess)",
        )
        .bind(subject)
        .bind(maximum)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(session)
    }

    pub async fn validate_session(
        &self,
        session: &str,
        idle_timeout_seconds: i64,
    ) -> Result<Option<String>, sqlx::Error> {
        self.validate_session_details(session, idle_timeout_seconds)
            .await
            .map(|validated| validated.map(|validated| validated.subject))
    }

    pub async fn validate_session_details(
        &self,
        session: &str,
        idle_timeout_seconds: i64,
    ) -> Result<Option<ValidatedSession>, sqlx::Error> {
        sqlx::query_as(
            "UPDATE authenticated_sessions SET last_seen_at = now()
             WHERE session_hash = $1 AND revoked_at IS NULL
               AND absolute_expires_at > now()
               AND last_seen_at > now() - ($2 * interval '1 second')
             RETURNING subject, created_at AS authenticated_at, mfa_verified",
        )
        .bind(digest(session))
        .bind(idle_timeout_seconds)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn revoke_session(&self, session: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE authenticated_sessions SET revoked_at = now()
             WHERE session_hash = $1",
        )
        .bind(digest(session))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn issue_pending_authorization(
        &self,
        grant: &AuthorizationGrant,
        state: &str,
    ) -> Result<String, sqlx::Error> {
        let transaction = random_token();
        sqlx::query(
            "INSERT INTO pending_authorizations
             (transaction_hash, issuer, subject, client_id, redirect_uri, scopes, state,
              nonce, code_challenge, response_mode, resource, dpop_jkt, auth_time, mfa_verified,
              claims, authorization_details, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(digest(&transaction))
        .bind(&grant.issuer)
        .bind(&grant.subject)
        .bind(&grant.client_id)
        .bind(&grant.redirect_uri)
        .bind(&grant.scopes)
        .bind(state)
        .bind(&grant.nonce)
        .bind(&grant.code_challenge)
        .bind(&grant.response_mode)
        .bind(&grant.resource)
        .bind(&grant.dpop_jkt)
        .bind(grant.auth_time)
        .bind(grant.mfa_verified)
        .bind(&grant.claims)
        .bind(&grant.authorization_details)
        .bind(grant.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(transaction)
    }

    pub async fn consume_pending_authorization(
        &self,
        transaction: &str,
    ) -> Result<Option<PendingAuthorization>, sqlx::Error> {
        sqlx::query_as(
            "DELETE FROM pending_authorizations WHERE transaction_hash = $1
             RETURNING issuer, subject, client_id, redirect_uri, scopes, state, nonce,
                       code_challenge, response_mode, resource, dpop_jkt, auth_time, mfa_verified,
                       claims, authorization_details, expires_at",
        )
        .bind(digest(transaction))
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn issue_logout_transaction(
        &self,
        return_to: Option<&str>,
    ) -> Result<String, sqlx::Error> {
        let transaction = random_token();
        sqlx::query(
            "INSERT INTO logout_transactions (transaction_hash, return_to, expires_at)
             VALUES ($1, $2, now() + interval '5 minutes')",
        )
        .bind(digest(&transaction))
        .bind(return_to)
        .execute(&self.pool)
        .await?;
        Ok(transaction)
    }

    pub async fn consume_logout_transaction(
        &self,
        transaction: &str,
    ) -> Result<Option<Option<String>>, sqlx::Error> {
        sqlx::query_scalar(
            "DELETE FROM logout_transactions
             WHERE transaction_hash = $1 AND expires_at > now()
             RETURNING return_to",
        )
        .bind(digest(transaction))
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn signing_key(&self, issuer: &str) -> Result<SigningKey, sqlx::Error> {
        if let Some(key) = self.find_signing_key(issuer).await? {
            return Ok(key);
        }

        let generated = generate_signing_key_async().await?;
        let (ciphertext, nonce) = self.encrypt_private_key(&generated.private_key_pem);
        sqlx::query(
            "INSERT INTO signing_keys
             (issuer, kid, private_key_ciphertext, private_key_nonce, modulus, exponent)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (issuer) DO NOTHING",
        )
        .bind(issuer)
        .bind(&generated.kid)
        .bind(ciphertext)
        .bind(nonce)
        .bind(&generated.modulus)
        .bind(&generated.exponent)
        .execute(&self.pool)
        .await?;

        self.find_signing_key(issuer)
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }

    pub async fn verification_signing_keys(
        &self,
        issuer: &str,
    ) -> Result<Vec<PublicSigningKey>, sqlx::Error> {
        self.public_signing_keys(issuer).await
    }

    pub async fn public_signing_keys(
        &self,
        issuer: &str,
    ) -> Result<Vec<PublicSigningKey>, sqlx::Error> {
        let _ = self.signing_key(issuer).await?;
        sqlx::query_as(
            "SELECT kid, modulus, exponent FROM signing_keys WHERE issuer = $1
             UNION ALL
             SELECT kid, modulus, exponent FROM retained_signing_keys WHERE issuer = $1
             ORDER BY kid",
        )
        .bind(issuer)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn rotate_signing_key(
        &self,
        issuer: &str,
        rotation_id: &str,
        retention_seconds: i64,
    ) -> Result<(SigningKey, bool), sqlx::Error> {
        if !valid_rotation_id(rotation_id) {
            return Err(sqlx::Error::Protocol(
                "rotation identifier must contain 1 to 128 URL-safe characters".to_owned(),
            ));
        }
        if !(1..=604_800).contains(&retention_seconds) {
            return Err(sqlx::Error::Protocol(
                "signing key retention must contain 1 to 604800 seconds".to_owned(),
            ));
        }
        let _ = self.signing_key(issuer).await?;
        let mut transaction = self.pool.begin().await?;
        let current_rotation_id: Option<String> =
            sqlx::query_scalar("SELECT rotation_id FROM signing_keys WHERE issuer = $1 FOR UPDATE")
                .bind(issuer)
                .fetch_one(&mut *transaction)
                .await?;
        if current_rotation_id.as_deref() == Some(rotation_id) {
            transaction.commit().await?;
            tracing::info!(
                event = "signing_key_rotation",
                outcome = "unchanged",
                issuer,
                rotation_id
            );
            let key = self
                .find_signing_key(issuer)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
            return Ok((key, false));
        }

        let generated = generate_signing_key_async().await?;
        let (ciphertext, nonce) = self.encrypt_private_key(&generated.private_key_pem);

        sqlx::query(
            "INSERT INTO retained_signing_keys
             (issuer, kid, private_key_ciphertext, private_key_nonce, modulus, exponent,
              retired_at, retain_until)
             SELECT issuer, kid, private_key_ciphertext, private_key_nonce, modulus, exponent,
                    now(), now() + ($2 * interval '1 second')
             FROM signing_keys WHERE issuer = $1
             ON CONFLICT (issuer, kid) DO NOTHING",
        )
        .bind(issuer)
        .bind(retention_seconds)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE signing_keys SET
               kid = $2, private_key_ciphertext = $3, private_key_nonce = $4,
               modulus = $5, exponent = $6, rotation_id = $7, created_at = now()
             WHERE issuer = $1",
        )
        .bind(issuer)
        .bind(&generated.kid)
        .bind(ciphertext)
        .bind(nonce)
        .bind(&generated.modulus)
        .bind(&generated.exponent)
        .bind(rotation_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        tracing::info!(
            event = "signing_key_rotation",
            outcome = "rotated",
            issuer,
            rotation_id,
            kid = %generated.kid
        );
        Ok((generated, true))
    }

    pub async fn rotate_signing_key_if_due(
        &self,
        issuer: &str,
        rotation_interval_seconds: i64,
        retention_seconds: i64,
        now: DateTime<Utc>,
    ) -> Result<(SigningKey, bool), sqlx::Error> {
        if !(3_600..=31_536_000).contains(&rotation_interval_seconds) {
            return Err(sqlx::Error::Protocol(
                "automatic signing key rotation must contain 3600 to 31536000 seconds".to_owned(),
            ));
        }
        if !(1..=604_800).contains(&retention_seconds) {
            return Err(sqlx::Error::Protocol(
                "signing key retention must contain 1 to 604800 seconds".to_owned(),
            ));
        }
        let _ = self.signing_key(issuer).await?;
        let mut transaction = self.pool.begin().await?;
        let (current_kid, created_at): (String, DateTime<Utc>) =
            sqlx::query_as("SELECT kid, created_at FROM signing_keys WHERE issuer = $1 FOR UPDATE")
                .bind(issuer)
                .fetch_one(&mut *transaction)
                .await?;
        if created_at + chrono::Duration::seconds(rotation_interval_seconds) > now {
            transaction.commit().await?;
            let key = self
                .find_signing_key(issuer)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
            return Ok((key, false));
        }

        let generated = generate_signing_key_async().await?;
        let (ciphertext, nonce) = self.encrypt_private_key(&generated.private_key_pem);
        let rotation_id = format!("automatic-{current_kid}");
        let retain_until = now + chrono::Duration::seconds(retention_seconds);
        sqlx::query(
            "INSERT INTO retained_signing_keys
             (issuer, kid, private_key_ciphertext, private_key_nonce, modulus, exponent,
              retired_at, retain_until)
             SELECT issuer, kid, private_key_ciphertext, private_key_nonce, modulus, exponent,
                    $2, $3
             FROM signing_keys WHERE issuer = $1
             ON CONFLICT (issuer, kid) DO NOTHING",
        )
        .bind(issuer)
        .bind(now)
        .bind(retain_until)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE signing_keys SET
               kid = $2, private_key_ciphertext = $3, private_key_nonce = $4,
               modulus = $5, exponent = $6, rotation_id = $7, created_at = $8
             WHERE issuer = $1",
        )
        .bind(issuer)
        .bind(&generated.kid)
        .bind(ciphertext)
        .bind(nonce)
        .bind(&generated.modulus)
        .bind(&generated.exponent)
        .bind(&rotation_id)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        tracing::info!(
            event = "signing_key_rotation",
            outcome = "rotated",
            issuer,
            rotation_id,
            rotation_interval_seconds,
            kid = %generated.kid,
            "signing key rotated automatically"
        );
        Ok((generated, true))
    }

    pub async fn prune_retained_signing_keys(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM retained_signing_keys
             WHERE retain_until <= now()",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn reencrypt_signing_keys(&self) -> Result<ReencryptedSigningKeys, sqlx::Error> {
        if self.previous_key_encryption_key.is_none() {
            return Err(sqlx::Error::Protocol(
                "KEY_ENCRYPTION_SECRET_PREVIOUS is required for signing key re-encryption"
                    .to_owned(),
            ));
        }
        let mut transaction = self.pool.begin().await?;
        let active = sqlx::query_as::<_, EncryptedSigningKey>(
            "SELECT issuer, kid, private_key_ciphertext, private_key_nonce
             FROM signing_keys ORDER BY issuer FOR UPDATE",
        )
        .fetch_all(&mut *transaction)
        .await?;
        let retained = sqlx::query_as::<_, EncryptedSigningKey>(
            "SELECT issuer, kid, private_key_ciphertext, private_key_nonce
             FROM retained_signing_keys ORDER BY issuer, kid FOR UPDATE",
        )
        .fetch_all(&mut *transaction)
        .await?;

        for key in &active {
            let private_key = self.decrypt_private_key_material(
                &key.private_key_ciphertext,
                &key.private_key_nonce,
            )?;
            let (ciphertext, nonce) = self.encrypt_private_key(&private_key);
            sqlx::query(
                "UPDATE signing_keys
                 SET private_key_ciphertext = $3, private_key_nonce = $4
                 WHERE issuer = $1 AND kid = $2",
            )
            .bind(&key.issuer)
            .bind(&key.kid)
            .bind(ciphertext)
            .bind(nonce)
            .execute(&mut *transaction)
            .await?;
        }
        for key in &retained {
            let private_key = self.decrypt_private_key_material(
                &key.private_key_ciphertext,
                &key.private_key_nonce,
            )?;
            let (ciphertext, nonce) = self.encrypt_private_key(&private_key);
            sqlx::query(
                "UPDATE retained_signing_keys
                 SET private_key_ciphertext = $3, private_key_nonce = $4
                 WHERE issuer = $1 AND kid = $2",
            )
            .bind(&key.issuer)
            .bind(&key.kid)
            .bind(ciphertext)
            .bind(nonce)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(ReencryptedSigningKeys {
            active: active.len() as u64,
            retained: retained.len() as u64,
        })
    }

    async fn find_signing_key(&self, issuer: &str) -> Result<Option<SigningKey>, sqlx::Error> {
        let stored = sqlx::query_as::<_, StoredSigningKey>(
            "SELECT kid, private_key_ciphertext, private_key_nonce, modulus, exponent
             FROM signing_keys WHERE issuer = $1",
        )
        .bind(issuer)
        .fetch_optional(&self.pool)
        .await?;
        stored.map(|key| self.decrypt_private_key(key)).transpose()
    }

    fn encrypt_private_key(&self, private_key: &str) -> (Vec<u8>, Vec<u8>) {
        let cipher = Aes256Gcm::new_from_slice(&self.key_encryption_key)
            .expect("AES-256 key has the correct length");
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).expect("operating system randomness is unavailable");
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), private_key.as_bytes())
            .expect("private key encryption failed");
        (ciphertext, nonce.to_vec())
    }

    fn private_digest(&self, value: &str) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key_encryption_key)
            .expect("HMAC accepts a 256-bit key");
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    fn decrypt_private_key(&self, key: StoredSigningKey) -> Result<SigningKey, sqlx::Error> {
        let private_key_pem =
            self.decrypt_private_key_material(&key.private_key_ciphertext, &key.private_key_nonce)?;
        Ok(SigningKey {
            kid: key.kid,
            private_key_pem,
            modulus: key.modulus,
            exponent: key.exponent,
        })
    }

    fn decrypt_private_key_material(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<String, sqlx::Error> {
        if nonce.len() != 12 {
            return Err(sqlx::Error::Decode("invalid signing key nonce".into()));
        }
        let decrypt = |key: &[u8; 32]| {
            let cipher =
                Aes256Gcm::new_from_slice(key).expect("AES-256 key has the correct length");
            cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        };
        let plaintext = decrypt(&self.key_encryption_key)
            .or_else(|_| {
                self.previous_key_encryption_key
                    .as_ref()
                    .ok_or(aes_gcm::Error)
                    .and_then(decrypt)
            })
            .map_err(|_| sqlx::Error::Decode("signing key decryption failed".into()))?;
        String::from_utf8(plaintext)
            .map_err(|_| sqlx::Error::Decode("signing key is not UTF-8".into()))
    }
}

fn valid_rotation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn database_url_from_components(
    host: &str,
    port: &str,
    database: &str,
    user: &str,
    password: &str,
) -> Option<String> {
    if [host, database, user, password]
        .iter()
        .any(|value| value.is_empty())
    {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    let mut url = url::Url::parse("postgres://localhost/postgres").ok()?;
    url.set_host(Some(host)).ok()?;
    url.set_port(Some(port)).ok()?;
    url.set_username(user).ok()?;
    url.set_password(Some(password)).ok()?;
    url.set_path(&format!("/{database}"));
    Some(url.into())
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("operating system randomness is unavailable");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random_user_code() -> String {
    const ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXY";
    let mut code = String::with_capacity(8);
    while code.len() < 8 {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).expect("operating system randomness is unavailable");
        for byte in bytes.into_iter().filter(|byte| *byte < 240) {
            code.push(char::from(ALPHABET[usize::from(byte) % ALPHABET.len()]));
            if code.len() == 8 {
                break;
            }
        }
    }
    code
}

fn format_user_code(code: &str) -> String {
    format!("{}-{}", &code[..4], &code[4..])
}

fn valid_opaque_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn digest(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

fn generate_signing_key() -> SigningKey {
    let mut rng = rand_core::OsRng;
    let private = RsaPrivateKey::new(&mut rng, 2048).expect("RSA key generation failed");
    let public = private.to_public_key();
    let mut kid_bytes = [0_u8; 16];
    getrandom::fill(&mut kid_bytes).expect("operating system randomness is unavailable");

    SigningKey {
        kid: URL_SAFE_NO_PAD.encode(kid_bytes),
        private_key_pem: private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("RSA PEM encoding failed")
            .to_string(),
        modulus: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        exponent: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    }
}

async fn generate_signing_key_async() -> Result<SigningKey, sqlx::Error> {
    tokio::task::spawn_blocking(generate_signing_key)
        .await
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        DatabaseConfigurationError, DatabaseEnvironment, database_url_from_components,
        format_user_code, random_user_code, valid_rotation_id,
    };

    #[test]
    fn builds_a_postgres_url_and_percent_encodes_credentials() {
        let url = database_url_from_components(
            "postgres.internal",
            "5433",
            "robine_id",
            "robine user",
            "p@ss:/word",
        )
        .expect("database URL");

        assert_eq!(
            url,
            "postgres://robine%20user:p%40ss%3A%2Fword@postgres.internal:5433/robine_id"
        );
    }

    #[test]
    fn rejects_an_invalid_postgres_port() {
        assert!(
            database_url_from_components("postgres", "invalid", "db", "user", "password").is_none()
        );
        assert!(database_url_from_components("postgres", "5432", "db", "user", "").is_none());
    }

    #[test]
    fn rejects_partial_or_invalid_database_environment() {
        assert!(
            DatabaseEnvironment::default()
                .build()
                .expect("empty database environment")
                .is_none()
        );

        assert!(matches!(
            DatabaseEnvironment {
                key_encryption_secret: Some("x".repeat(32)),
                ..Default::default()
            }
            .build(),
            Err(DatabaseConfigurationError::IncompleteCredentials)
        ));
        assert!(matches!(
            DatabaseEnvironment {
                database_url: Some("postgres://database/robine_id".to_owned()),
                ..Default::default()
            }
            .build(),
            Err(DatabaseConfigurationError::MissingEncryptionSecret)
        ));
        assert!(matches!(
            DatabaseEnvironment {
                database_url: Some("postgres://database/robine_id".to_owned()),
                key_encryption_secret: Some("weak".to_owned()),
                ..Default::default()
            }
            .build(),
            Err(DatabaseConfigurationError::WeakEncryptionSecret)
        ));
        assert!(matches!(
            DatabaseEnvironment {
                database_url: Some("postgres://database/robine_id".to_owned()),
                key_encryption_secret: Some("x".repeat(32)),
                previous_key_encryption_secret: Some("weak".to_owned()),
                ..Default::default()
            }
            .build(),
            Err(DatabaseConfigurationError::WeakPreviousEncryptionSecret)
        ));
        assert!(matches!(
            DatabaseEnvironment {
                database_url: Some("postgres://database/robine_id".to_owned()),
                key_encryption_secret: Some("x".repeat(32)),
                previous_key_encryption_secret: Some("x".repeat(32)),
                ..Default::default()
            }
            .build(),
            Err(DatabaseConfigurationError::MatchingEncryptionSecrets)
        ));
        assert!(matches!(
            DatabaseEnvironment {
                database_url: Some("postgres://database/robine_id".to_owned()),
                key_encryption_secret: Some("x".repeat(32)),
                maximum_connections: Some("0".to_owned()),
                ..Default::default()
            }
            .build(),
            Err(DatabaseConfigurationError::InvalidInteger {
                name: "DATABASE_MAX_CONNECTIONS",
                minimum: 1,
                maximum: 50
            })
        ));
        assert!(matches!(
            DatabaseEnvironment {
                pg_host: Some("database".to_owned()),
                ..Default::default()
            }
            .build(),
            Err(DatabaseConfigurationError::IncompleteCredentials)
        ));
    }

    #[tokio::test]
    async fn accepts_strict_url_and_component_database_environments() {
        assert!(
            DatabaseEnvironment {
                database_url: Some("postgres://user:password@database/robine_id".to_owned()),
                key_encryption_secret: Some("x".repeat(32)),
                previous_key_encryption_secret: Some("y".repeat(32)),
                maximum_connections: Some("10".to_owned()),
                acquire_timeout_ms: Some("2500".to_owned()),
                statement_timeout_ms: Some("3000".to_owned()),
                ..Default::default()
            }
            .build()
            .expect("direct database environment")
            .is_some()
        );
        assert!(
            DatabaseEnvironment {
                pg_host: Some("database".to_owned()),
                pg_password: Some("password".to_owned()),
                key_encryption_secret: Some("x".repeat(32)),
                vercel: true,
                ..Default::default()
            }
            .build()
            .expect("component database environment")
            .is_some()
        );
    }

    #[test]
    fn accepts_only_bounded_url_safe_rotation_identifiers() {
        assert!(valid_rotation_id("deployment-2026_08.17~blue"));
        assert!(!valid_rotation_id(""));
        assert!(!valid_rotation_id("contains spaces"));
        assert!(!valid_rotation_id(&"x".repeat(129)));
    }

    #[test]
    fn generates_unambiguous_high_entropy_device_user_codes() {
        let codes = (0..128)
            .map(|_| random_user_code())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(codes.len(), 128);
        for code in codes {
            assert_eq!(code.len(), 8);
            assert!(
                code.bytes()
                    .all(|byte| b"BCDFGHJKLMNPQRSTVWXY".contains(&byte))
            );
            let formatted = format_user_code(&code);
            assert_eq!(formatted.len(), 9);
            assert_eq!(formatted.replace('-', ""), code);
        }
    }

    #[tokio::test]
    async fn previous_encryption_key_reads_old_rows_while_new_rows_use_the_current_key() {
        let old_secret = "old-key-encryption-secret-at-least-32-bytes".to_owned();
        let new_secret = "new-key-encryption-secret-at-least-32-bytes".to_owned();
        let old = super::Database::configured(
            "postgres://database/robine_id".to_owned(),
            old_secret.clone(),
            None,
            1,
            1_000,
            1_000,
        )
        .expect("old encryption configuration");
        let staged = super::Database::configured(
            "postgres://database/robine_id".to_owned(),
            new_secret.clone(),
            Some(old_secret),
            1,
            1_000,
            1_000,
        )
        .expect("staged encryption configuration");
        let current_only = super::Database::configured(
            "postgres://database/robine_id".to_owned(),
            new_secret,
            None,
            1,
            1_000,
            1_000,
        )
        .expect("current encryption configuration");

        let (old_ciphertext, old_nonce) = old.encrypt_private_key("old private key");
        assert_eq!(
            staged
                .decrypt_private_key_material(&old_ciphertext, &old_nonce)
                .unwrap(),
            "old private key"
        );
        assert!(
            current_only
                .decrypt_private_key_material(&old_ciphertext, &old_nonce)
                .is_err()
        );

        let (new_ciphertext, new_nonce) = staged.encrypt_private_key("new private key");
        assert_eq!(
            current_only
                .decrypt_private_key_material(&new_ciphertext, &new_nonce)
                .unwrap(),
            "new private key"
        );
    }
}
