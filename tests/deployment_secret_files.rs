use std::{
    ffi::OsStr,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn temporary_directory(label: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "robine-id-cli-{label}-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn cli_creates_protected_files_once_and_refuses_to_replace_them() {
    let directory = temporary_directory("deployment-secrets");
    let binary = env!("CARGO_BIN_EXE_generate_deployment_secrets");
    let first = Command::new(binary)
        .args([OsStr::new("--directory"), directory.as_os_str()])
        .output()
        .expect("run deployment-secret file generator");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );

    let database_path = directory.join("postgres_password");
    let encryption_path = directory.join("key_encryption_secret");
    let database_password = fs::read(&database_path).expect("database password file");
    let encryption_secret = fs::read(&encryption_path).expect("key encryption secret file");
    assert_eq!(database_password.len(), 64);
    assert_eq!(encryption_secret.len(), 64);
    assert_ne!(database_password, encryption_secret);
    assert!(
        !first
            .stdout
            .windows(database_password.len())
            .any(|window| window == database_password)
    );
    assert!(
        !first
            .stdout
            .windows(encryption_secret.len())
            .any(|window| window == encryption_secret)
    );
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for path in [&database_path, &encryption_path] {
            assert_eq!(
                fs::metadata(path)
                    .expect("file metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    let retry = Command::new(binary)
        .args([OsStr::new("--directory"), directory.as_os_str()])
        .output()
        .expect("retry deployment-secret file generator");
    assert!(!retry.status.success());
    assert!(String::from_utf8_lossy(&retry.stderr).contains("refusing to overwrite"));
    assert_eq!(
        fs::read(&database_path).expect("unchanged database password"),
        database_password
    );
    assert_eq!(
        fs::read(&encryption_path).expect("unchanged encryption secret"),
        encryption_secret
    );

    fs::remove_dir_all(directory).expect("remove generated secret directory");
}

#[test]
fn cli_rejects_incomplete_or_unknown_arguments() {
    let binary = env!("CARGO_BIN_EXE_generate_deployment_secrets");
    for arguments in [vec!["--directory"], vec!["--unknown"]] {
        let output = Command::new(binary)
            .args(arguments)
            .output()
            .expect("run invalid deployment-secret generator command");
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("generate_deployment_secrets [--directory PATH]")
        );
    }
}
