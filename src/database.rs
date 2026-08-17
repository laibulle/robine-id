use crate::protocol::AuthorizationGrant;
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

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
    key_encryption_key: [u8; 32],
}

#[derive(Debug, sqlx::FromRow)]
pub struct AccessGrant {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub claims: Value,
    pub expires_at: DateTime<Utc>,
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
    pub claims: Value,
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

impl Database {
    pub fn from_env() -> Option<Self> {
        let url = env::var("DATABASE_URL")
            .ok()
            .or_else(database_url_from_postgres_environment)?;
        let secret = env::var("KEY_ENCRYPTION_SECRET")
            .or_else(|_| env::var("SECRET_KEY_BASE"))
            .ok()?;
        if secret.len() < 32 {
            tracing::error!(
                event = "database_configuration",
                "KEY_ENCRYPTION_SECRET or SECRET_KEY_BASE must contain at least 32 bytes"
            );
            return None;
        }
        let key_encryption_key: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        let default_connections = if env::var_os("VERCEL").is_some() {
            2
        } else {
            5
        };
        let maximum_connections = env::var("DATABASE_MAX_CONNECTIONS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| (1..=50).contains(value))
            .unwrap_or(default_connections);
        PgPoolOptions::new()
            .max_connections(maximum_connections)
            .connect_lazy(&url)
            .ok()
            .map(|pool| Self {
                pool,
                key_encryption_key,
            })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::migrate!().run(&self.pool).await?;
        self.cleanup_expired_state().await
    }

    async fn cleanup_expired_state(&self) -> Result<(), sqlx::Error> {
        for statement in [
            "DELETE FROM authorization_codes WHERE expires_at <= now()",
            "DELETE FROM access_tokens WHERE expires_at <= now()",
            "DELETE FROM pending_authorizations WHERE expires_at <= now()",
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

    pub async fn issue_authorization_code(
        &self,
        grant: &AuthorizationGrant,
    ) -> Result<String, sqlx::Error> {
        let code = random_token();
        let hash = digest(&code);
        sqlx::query(
            "INSERT INTO authorization_codes
             (code_hash, issuer, subject, client_id, redirect_uri, scopes, nonce, code_challenge, claims, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(hash)
        .bind(&grant.issuer)
        .bind(&grant.subject)
        .bind(&grant.client_id)
        .bind(&grant.redirect_uri)
        .bind(&grant.scopes)
        .bind(&grant.nonce)
        .bind(&grant.code_challenge)
        .bind(&grant.claims)
        .bind(grant.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(code)
    }

    pub async fn consume_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationGrant>, sqlx::Error> {
        sqlx::query_as::<_, AuthorizationGrant>(
            "DELETE FROM authorization_codes WHERE code_hash = $1
             RETURNING issuer, subject, client_id, redirect_uri, scopes, nonce,
                       code_challenge, claims, expires_at",
        )
        .bind(digest(code))
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn issue_access_token(&self, grant: &AccessGrant) -> Result<String, sqlx::Error> {
        let token = random_token();
        sqlx::query(
            "INSERT INTO access_tokens
             (token_hash, issuer, subject, client_id, scopes, claims, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(digest(&token))
        .bind(&grant.issuer)
        .bind(&grant.subject)
        .bind(&grant.client_id)
        .bind(&grant.scopes)
        .bind(&grant.claims)
        .bind(grant.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    pub async fn access_grant(&self, token: &str) -> Result<Option<AccessGrant>, sqlx::Error> {
        sqlx::query_as::<_, AccessGrant>(
            "SELECT issuer, subject, client_id, scopes, claims, expires_at
             FROM access_tokens WHERE token_hash = $1 AND expires_at > now()",
        )
        .bind(digest(token))
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn allow_authentication_attempt(
        &self,
        key: &str,
        limit: i32,
        window_seconds: i32,
    ) -> Result<bool, sqlx::Error> {
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
        .fetch_one(&self.pool)
        .await?;
        Ok(attempts <= limit)
    }

    pub async fn start_session(
        &self,
        subject: &str,
        maximum: i64,
        absolute_timeout_seconds: i64,
    ) -> Result<String, sqlx::Error> {
        let session = random_token();
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO authenticated_sessions
             (session_hash, subject, absolute_expires_at)
             VALUES ($1, $2, now() + ($3 * interval '1 second'))",
        )
        .bind(digest(&session))
        .bind(subject)
        .bind(absolute_timeout_seconds)
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
        sqlx::query_scalar(
            "UPDATE authenticated_sessions SET last_seen_at = now()
             WHERE session_hash = $1 AND revoked_at IS NULL
               AND absolute_expires_at > now()
               AND last_seen_at > now() - ($2 * interval '1 second')
             RETURNING subject",
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
              nonce, code_challenge, claims, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
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
        .bind(&grant.claims)
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
                       code_challenge, claims, expires_at",
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
    ) -> Result<Vec<SigningKey>, sqlx::Error> {
        let _ = self.signing_key(issuer).await?;
        let stored = sqlx::query_as::<_, StoredSigningKey>(
            "SELECT kid, private_key_ciphertext, private_key_nonce, modulus, exponent
             FROM signing_keys WHERE issuer = $1
             UNION ALL
             SELECT kid, private_key_ciphertext, private_key_nonce, modulus, exponent
             FROM retained_signing_keys WHERE issuer = $1",
        )
        .bind(issuer)
        .fetch_all(&self.pool)
        .await?;
        stored
            .into_iter()
            .map(|key| self.decrypt_private_key(key))
            .collect()
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
    ) -> Result<(SigningKey, bool), sqlx::Error> {
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
             (issuer, kid, private_key_ciphertext, private_key_nonce, modulus, exponent)
             SELECT issuer, kid, private_key_ciphertext, private_key_nonce, modulus, exponent
             FROM signing_keys WHERE issuer = $1
             ON CONFLICT (issuer, kid) DO NOTHING",
        )
        .bind(issuer)
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
        if key.private_key_nonce.len() != 12 {
            return Err(sqlx::Error::Decode("invalid signing key nonce".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key_encryption_key)
            .expect("AES-256 key has the correct length");
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&key.private_key_nonce),
                key.private_key_ciphertext.as_ref(),
            )
            .map_err(|_| sqlx::Error::Decode("signing key decryption failed".into()))?;
        let private_key_pem = String::from_utf8(plaintext)
            .map_err(|_| sqlx::Error::Decode("signing key is not UTF-8".into()))?;
        Ok(SigningKey {
            kid: key.kid,
            private_key_pem,
            modulus: key.modulus,
            exponent: key.exponent,
        })
    }
}

fn database_url_from_postgres_environment() -> Option<String> {
    let host = env::var("PGHOST").ok()?;
    let port = env::var("PGPORT").unwrap_or_else(|_| "5432".to_owned());
    let database = env::var("PGDATABASE").unwrap_or_else(|_| "robine_id".to_owned());
    let user = env::var("PGUSER").unwrap_or_else(|_| "robine_id".to_owned());
    let password = env::var("PGPASSWORD")
        .or_else(|_| env::var("POSTGRES_PASSWORD"))
        .ok()?;
    database_url_from_components(&host, &port, &database, &user, &password)
}

fn database_url_from_components(
    host: &str,
    port: &str,
    database: &str,
    user: &str,
    password: &str,
) -> Option<String> {
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
    use super::database_url_from_components;

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
            database_url_from_components("postgres", "invalid", "db", "user", "password")
                .is_none()
        );
    }
}
