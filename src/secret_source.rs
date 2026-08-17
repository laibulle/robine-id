use std::{env, fs::File, io::Read, path::Path};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const MAXIMUM_SECRET_FILE_BYTES: usize = 16 * 1024;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SecretSourceError {
    #[error("secret environment variable {name} is not valid Unicode")]
    NonUnicodeEnvironment { name: String },
    #[error("{value_name} and {file_name} are mutually exclusive")]
    ConflictingSources {
        value_name: String,
        file_name: String,
    },
    #[error("secret file configured by {name} could not be read")]
    UnreadableFile { name: String },
    #[error("secret file configured by {name} exceeds 16384 bytes")]
    OversizedFile { name: String },
    #[error("secret file configured by {name} is not valid UTF-8")]
    NonUnicodeFile { name: String },
}

pub fn from_environment(value_name: &str) -> Result<Option<Zeroizing<String>>, SecretSourceError> {
    let file_name = format!("{value_name}_FILE");
    from_environment_names(value_name, &file_name)
}

pub(crate) fn from_environment_names(
    value_name: &str,
    file_name: &str,
) -> Result<Option<Zeroizing<String>>, SecretSourceError> {
    let value = environment_value(value_name)?.map(Zeroizing::new);
    let file_path = environment_value(file_name)?;
    resolve_sources(value_name, value, file_name, file_path.as_deref())
}

fn environment_value(name: &str) -> Result<Option<String>, SecretSourceError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(SecretSourceError::NonUnicodeEnvironment {
            name: name.to_owned(),
        }),
    }
}

fn resolve_sources(
    value_name: &str,
    value: Option<Zeroizing<String>>,
    file_name: &str,
    file_path: Option<&str>,
) -> Result<Option<Zeroizing<String>>, SecretSourceError> {
    match (value, file_path) {
        (Some(_), Some(_)) => Err(SecretSourceError::ConflictingSources {
            value_name: value_name.to_owned(),
            file_name: file_name.to_owned(),
        }),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(file_path)) => read_file(file_name, Path::new(file_path)).map(Some),
        (None, None) => Ok(None),
    }
}

fn read_file(name: &str, path: &Path) -> Result<Zeroizing<String>, SecretSourceError> {
    let file = File::open(path).map_err(|_| SecretSourceError::UnreadableFile {
        name: name.to_owned(),
    })?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(256));
    file.take((MAXIMUM_SECRET_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SecretSourceError::UnreadableFile {
            name: name.to_owned(),
        })?;
    if bytes.len() > MAXIMUM_SECRET_FILE_BYTES {
        return Err(SecretSourceError::OversizedFile {
            name: name.to_owned(),
        });
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(SecretSourceError::NonUnicodeFile {
                name: name.to_owned(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    fn temporary_secret_path(label: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "robine-id-{label}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn reads_bounded_files_and_removes_one_line_ending() {
        let unix_path = temporary_secret_path("secret-unix");
        let windows_path = temporary_secret_path("secret-windows");
        fs::write(&unix_path, b"database-password\n").expect("write Unix secret file");
        fs::write(&windows_path, b"wrapping-secret\r\n").expect("write Windows secret file");

        assert_eq!(
            read_file("POSTGRES_PASSWORD_FILE", &unix_path)
                .expect("read Unix secret")
                .as_str(),
            "database-password"
        );
        assert_eq!(
            read_file("KEY_ENCRYPTION_SECRET_FILE", &windows_path)
                .expect("read Windows secret")
                .as_str(),
            "wrapping-secret"
        );

        fs::remove_file(unix_path).expect("remove Unix secret file");
        fs::remove_file(windows_path).expect("remove Windows secret file");
    }

    #[test]
    fn rejects_conflicting_unreadable_oversized_and_non_unicode_sources() {
        assert!(matches!(
            resolve_sources(
                "KEY_ENCRYPTION_SECRET",
                Some("direct-secret".to_owned().into()),
                "KEY_ENCRYPTION_SECRET_FILE",
                Some("not-opened"),
            ),
            Err(SecretSourceError::ConflictingSources { .. })
        ));

        let absent_path = temporary_secret_path("absent");
        let error = read_file("KEY_ENCRYPTION_SECRET_FILE", &absent_path)
            .expect_err("missing file must fail");
        assert!(matches!(error, SecretSourceError::UnreadableFile { .. }));
        assert!(
            !error
                .to_string()
                .contains(absent_path.to_string_lossy().as_ref())
        );

        let oversized_path = temporary_secret_path("secret-oversized");
        fs::write(&oversized_path, vec![b'x'; MAXIMUM_SECRET_FILE_BYTES + 1])
            .expect("write oversized secret file");
        assert!(matches!(
            read_file("DATABASE_URL_FILE", &oversized_path),
            Err(SecretSourceError::OversizedFile { .. })
        ));
        fs::remove_file(oversized_path).expect("remove oversized secret file");

        let non_unicode_path = temporary_secret_path("secret-non-unicode");
        fs::write(&non_unicode_path, [0xff, 0xfe]).expect("write non-Unicode secret file");
        assert!(matches!(
            read_file("PGPASSWORD_FILE", &non_unicode_path),
            Err(SecretSourceError::NonUnicodeFile { .. })
        ));
        fs::remove_file(non_unicode_path).expect("remove non-Unicode secret file");
    }
}
