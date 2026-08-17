use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

const DEPLOYMENT_SECRET_BYTES: usize = 48;
const DATABASE_PASSWORD_FILE: &str = "postgres_password";
const KEY_ENCRYPTION_SECRET_FILE: &str = "key_encryption_secret";

#[derive(Debug, Error)]
pub enum SecretGenerationError {
    #[error("operating-system entropy is unavailable")]
    Entropy,
}

#[derive(Debug, Error)]
pub enum DeploymentSecretFilesError {
    #[error(transparent)]
    Generation(#[from] SecretGenerationError),
    #[error("deployment secret directory could not be prepared safely")]
    PrepareDirectory,
    #[error("{name} already exists; refusing to overwrite it")]
    AlreadyExists { name: &'static str },
    #[error("{name} could not be created safely")]
    CreateFile { name: &'static str },
    #[error("{name} could not be written durably")]
    WriteFile { name: &'static str },
}

#[derive(Debug, Eq, PartialEq)]
pub struct DeploymentSecretFiles {
    pub database_password: PathBuf,
    pub key_encryption_secret: PathBuf,
}

/// Generates deployment-specific wrapping material suitable for
/// `KEY_ENCRYPTION_SECRET`.
///
/// The encoded value contains 384 bits of operating-system entropy and only
/// uses characters that can be copied directly into an environment file.
pub fn generate_key_encryption_secret() -> Result<Zeroizing<String>, SecretGenerationError> {
    generate_deployment_secret()
}

/// Generates an independent URL-safe PostgreSQL password for release Compose.
pub fn generate_database_password() -> Result<Zeroizing<String>, SecretGenerationError> {
    generate_deployment_secret()
}

/// Creates the two canonical Compose secret files without replacing existing
/// material. On Unix, the destination directory is restricted to mode `0700`
/// and each newly created file to mode `0600`.
pub fn create_deployment_secret_files(
    directory: &Path,
) -> Result<DeploymentSecretFiles, DeploymentSecretFilesError> {
    let database_password = generate_database_password()?;
    let key_encryption_secret = generate_key_encryption_secret()?;
    prepare_secret_directory(directory)?;

    let database_path = directory.join(DATABASE_PASSWORD_FILE);
    let encryption_path = directory.join(KEY_ENCRYPTION_SECRET_FILE);
    ensure_secret_file_absent(&database_path, DATABASE_PASSWORD_FILE)?;
    ensure_secret_file_absent(&encryption_path, KEY_ENCRYPTION_SECRET_FILE)?;

    let mut database_file = create_secret_file(
        &database_path,
        DATABASE_PASSWORD_FILE,
        database_password.as_bytes(),
    )?;
    let mut encryption_file = create_secret_file(
        &encryption_path,
        KEY_ENCRYPTION_SECRET_FILE,
        key_encryption_secret.as_bytes(),
    )?;
    database_file.commit();
    encryption_file.commit();

    Ok(DeploymentSecretFiles {
        database_password: database_path,
        key_encryption_secret: encryption_path,
    })
}

fn generate_deployment_secret() -> Result<Zeroizing<String>, SecretGenerationError> {
    let mut entropy = [0_u8; DEPLOYMENT_SECRET_BYTES];
    getrandom::fill(&mut entropy).map_err(|_| SecretGenerationError::Entropy)?;
    let secret = URL_SAFE_NO_PAD.encode(entropy.as_slice());
    entropy.zeroize();
    Ok(Zeroizing::new(secret))
}

fn prepare_secret_directory(directory: &Path) -> Result<(), DeploymentSecretFilesError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() => {
            return Err(DeploymentSecretFilesError::PrepareDirectory);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            builder
                .create(directory)
                .map_err(|_| DeploymentSecretFilesError::PrepareDirectory)?;
        }
        Err(_) => return Err(DeploymentSecretFilesError::PrepareDirectory),
    }
    #[cfg(unix)]
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| DeploymentSecretFilesError::PrepareDirectory)?;
    Ok(())
}

fn ensure_secret_file_absent(
    path: &Path,
    name: &'static str,
) -> Result<(), DeploymentSecretFilesError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(DeploymentSecretFilesError::AlreadyExists { name }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DeploymentSecretFilesError::CreateFile { name }),
    }
}

fn create_secret_file(
    path: &Path,
    name: &'static str,
    secret: &[u8],
) -> Result<CreatedSecretFile, DeploymentSecretFilesError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            DeploymentSecretFilesError::AlreadyExists { name }
        } else {
            DeploymentSecretFilesError::CreateFile { name }
        }
    })?;
    let mut guard = CreatedSecretFile {
        file: Some(file),
        path: path.to_owned(),
        committed: false,
    };
    let file = guard
        .file
        .as_mut()
        .ok_or(DeploymentSecretFilesError::CreateFile { name })?;
    file.write_all(secret)
        .map_err(|_| DeploymentSecretFilesError::WriteFile { name })?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| DeploymentSecretFilesError::WriteFile { name })?;
    file.sync_all()
        .map_err(|_| DeploymentSecretFilesError::WriteFile { name })?;
    Ok(guard)
}

struct CreatedSecretFile {
    file: Option<File>,
    path: PathBuf,
    committed: bool,
}

impl CreatedSecretFile {
    fn commit(&mut self) {
        self.committed = true;
        self.file.take();
    }
}

impl Drop for CreatedSecretFile {
    fn drop(&mut self) {
        self.file.take();
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temporary_directory(label: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "robine-id-{label}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn generates_independent_env_safe_384_bit_secrets() {
        let first = generate_key_encryption_secret().expect("key encryption secret");
        let second = generate_database_password().expect("database password");

        assert_eq!(first.len(), 64);
        assert_ne!(first.as_str(), second.as_str());
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(first.as_bytes())
                .expect("canonical base64url secret")
                .len(),
            DEPLOYMENT_SECRET_BYTES
        );
    }

    #[test]
    fn creates_independent_canonical_secret_files_with_restrictive_permissions() {
        let directory = temporary_directory("deployment-secret-files");
        let files = create_deployment_secret_files(&directory).expect("create deployment secrets");
        let database_password = fs::read_to_string(&files.database_password).expect("database file");
        let key_encryption_secret =
            fs::read_to_string(&files.key_encryption_secret).expect("encryption file");

        assert_eq!(database_password.len(), 64);
        assert_eq!(key_encryption_secret.len(), 64);
        assert_ne!(database_password, key_encryption_secret);
        for secret in [&database_password, &key_encryption_secret] {
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(secret.as_bytes())
                    .expect("canonical Base64URL secret")
                    .len(),
                DEPLOYMENT_SECRET_BYTES
            );
        }
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&directory)
                    .expect("secret directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            for path in [&files.database_password, &files.key_encryption_secret] {
                assert_eq!(
                    fs::metadata(path)
                        .expect("secret file metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }

        fs::remove_dir_all(directory).expect("remove deployment secret directory");
    }

    #[test]
    fn refuses_to_replace_or_partially_create_secret_files() {
        let directory = temporary_directory("deployment-secret-collision");
        fs::create_dir(&directory).expect("create secret directory");
        let existing_path = directory.join(KEY_ENCRYPTION_SECRET_FILE);
        fs::write(&existing_path, "existing-secret").expect("write existing secret");

        assert!(matches!(
            create_deployment_secret_files(&directory),
            Err(DeploymentSecretFilesError::AlreadyExists {
                name: KEY_ENCRYPTION_SECRET_FILE
            })
        ));
        assert_eq!(
            fs::read_to_string(existing_path).expect("unchanged existing secret"),
            "existing-secret"
        );
        assert!(!directory.join(DATABASE_PASSWORD_FILE).exists());

        fs::remove_dir_all(directory).expect("remove collision directory");
    }
}
