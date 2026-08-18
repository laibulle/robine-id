use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

fn temporary_secret_path(label: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "robine-id-process-{label}-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

fn run_server(environment: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_robine-id"));
    command.current_dir(env!("CARGO_MANIFEST_DIR")).env_clear();
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().expect("run conventional server binary")
}

fn diagnostic(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn child_resolves_a_declarative_file_secret() {
    if std::env::var_os("ROBINE_ID_SECRET_SOURCE_CHILD").is_none() {
        return;
    }
    let secret = robine_id::secret_source::from_environment("DECLARATIVE_SECRET")
        .expect("valid declarative secret source")
        .expect("configured declarative secret");
    assert_eq!(secret.as_str(), "generic-file-secret");
}

#[test]
fn declarative_references_derive_their_file_source_name() {
    let path = temporary_secret_path("declarative-secret");
    fs::write(&path, "generic-file-secret\n").expect("write declarative secret file");
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "child_resolves_a_declarative_file_secret",
            "--nocapture",
        ])
        .env_clear()
        .env("ROBINE_ID_SECRET_SOURCE_CHILD", "1")
        .env("DECLARATIVE_SECRET_FILE", &path)
        .output()
        .expect("run isolated declarative-secret test");

    assert!(output.status.success(), "{}", diagnostic(&output));
    fs::remove_file(path).expect("remove declarative secret file");
}

#[test]
fn process_rejects_direct_and_file_sources_without_disclosing_either() {
    let path = temporary_secret_path("conflicting-secret-path-marker");
    fs::write(&path, "file-secret-value-marker\n").expect("write conflicting secret file");
    let path_text = path.to_string_lossy().into_owned();
    let output = run_server(&[
        (
            "DATABASE_URL",
            "postgres://user:direct-password-marker@database/robine_id",
        ),
        ("DATABASE_URL_FILE", &path_text),
        ("KEY_ENCRYPTION_SECRET", &"x".repeat(32)),
    ]);
    let diagnostic = diagnostic(&output);

    assert!(!output.status.success());
    assert!(diagnostic.contains("DATABASE_URL and DATABASE_URL_FILE are mutually exclusive"));
    for sensitive in [
        "direct-password-marker",
        "file-secret-value-marker",
        path_text.as_str(),
    ] {
        assert!(!diagnostic.contains(sensitive));
    }

    fs::remove_file(path).expect("remove conflicting secret file");
}

#[test]
fn process_loads_file_sources_and_reports_policy_without_disclosing_them() {
    let database_path = temporary_secret_path("database-url-path-marker");
    let encryption_path = temporary_secret_path("encryption-key-path-marker");
    fs::write(
        &database_path,
        "postgres://user:file-password-marker@127.0.0.1:1/robine_id\n",
    )
    .expect("write database URL file");
    fs::write(&encryption_path, "weak-file-key-value-marker-123\n")
        .expect("write weak encryption secret file");
    let database_path_text = database_path.to_string_lossy().into_owned();
    let encryption_path_text = encryption_path.to_string_lossy().into_owned();
    let output = run_server(&[
        ("DATABASE_URL_FILE", &database_path_text),
        ("KEY_ENCRYPTION_SECRET_FILE", &encryption_path_text),
    ]);
    let diagnostic = diagnostic(&output);

    assert!(!output.status.success());
    assert!(diagnostic.contains("must contain at least 32 bytes"));
    for sensitive in [
        "file-password-marker",
        "weak-file-key-value-marker",
        database_path_text.as_str(),
        encryption_path_text.as_str(),
    ] {
        assert!(!diagnostic.contains(sensitive));
    }

    fs::remove_file(database_path).expect("remove database URL file");
    fs::remove_file(encryption_path).expect("remove encryption key file");
}

#[test]
fn process_validates_metrics_file_tokens_without_disclosing_them() {
    let invalid_path = temporary_secret_path("metrics-token-path-marker");
    let invalid_token = "metrics token value marker that contains spaces";
    fs::write(&invalid_path, format!("{invalid_token}\n")).expect("write invalid metrics token");
    let invalid_path_text = invalid_path.to_string_lossy().into_owned();
    let output = run_server(&[("METRICS_BEARER_TOKEN_FILE", &invalid_path_text)]);
    let invalid_diagnostic = diagnostic(&output);

    assert!(!output.status.success());
    assert!(invalid_diagnostic.contains(
        "METRICS_BEARER_TOKEN must contain between 32 and 256 URL-safe ASCII characters"
    ));
    assert!(!invalid_diagnostic.contains(invalid_token));
    assert!(!invalid_diagnostic.contains(&invalid_path_text));
    fs::remove_file(invalid_path).expect("remove invalid metrics token file");

    let valid_path = temporary_secret_path("valid-metrics-token-path-marker");
    let valid_token = "valid_metrics_token_abcdefghijklmnopqrstuvwxyz0123456789";
    fs::write(&valid_path, format!("{valid_token}\n")).expect("write valid metrics token");
    let valid_path_text = valid_path.to_string_lossy().into_owned();
    let output = run_server(&[
        ("METRICS_BEARER_TOKEN_FILE", &valid_path_text),
        ("DATABASE_URL", "not-a-database-url"),
    ]);
    let valid_diagnostic = diagnostic(&output);

    assert!(!output.status.success());
    assert!(!valid_diagnostic.contains("METRICS_BEARER_TOKEN must contain"));
    assert!(!valid_diagnostic.contains(valid_token));
    assert!(!valid_diagnostic.contains(&valid_path_text));
    fs::remove_file(valid_path).expect("remove valid metrics token file");
}
