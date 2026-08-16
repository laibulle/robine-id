use crate::protocol::AuthorizationGrant;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
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

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct SigningKey {
    pub kid: String,
    pub private_key_pem: String,
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
        let url = env::var("DATABASE_URL").ok()?;
        let secret = env::var("KEY_ENCRYPTION_SECRET")
            .or_else(|_| env::var("SECRET_KEY_BASE"))
            .ok()?;
        let key_encryption_key: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        PgPoolOptions::new()
            .max_connections(5)
            .connect_lazy(&url)
            .ok()
            .map(|pool| Self {
                pool,
                key_encryption_key,
            })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::migrate!().run(&self.pool).await.map_err(Into::into)
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
        .bind(digest(key))
        .bind(window_seconds)
        .fetch_one(&self.pool)
        .await?;
        Ok(attempts <= limit)
    }

    pub async fn signing_key(&self, issuer: &str) -> Result<SigningKey, sqlx::Error> {
        if let Some(key) = self.find_signing_key(issuer).await? {
            return Ok(key);
        }

        let generated = generate_signing_key();
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
