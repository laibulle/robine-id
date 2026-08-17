use std::process::{Command, Output};

fn run_doctor(environment: &[(&str, &str)], arguments: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_robine-id-doctor"));
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env_clear()
        .args(arguments);
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().expect("run doctor binary")
}

#[test]
fn doctor_requires_database_configuration_and_rejects_arguments() {
    let missing_database = run_doctor(&[], &[]);
    assert!(!missing_database.status.success());
    assert!(String::from_utf8_lossy(&missing_database.stderr).contains("DATABASE_URL is required"));

    let unexpected_argument = run_doctor(&[], &["unexpected"]);
    assert!(!unexpected_argument.status.success());
    assert!(
        String::from_utf8_lossy(&unexpected_argument.stderr).contains("usage: robine-id-doctor")
    );
}

#[test]
fn doctor_reports_unreachable_database_without_disclosing_credentials() {
    let output = run_doctor(
        &[
            (
                "DATABASE_URL",
                "postgres://operator:doctor-password-marker@127.0.0.1:1/robine_id",
            ),
            (
                "KEY_ENCRYPTION_SECRET",
                "doctor-wrapping-secret-marker-32-bytes",
            ),
            ("DATABASE_ACQUIRE_TIMEOUT_MS", "100"),
            ("DATABASE_STATEMENT_TIMEOUT_MS", "100"),
        ],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stdout.contains("\"status\": \"not_ready\""));
    assert!(stdout.contains("\"connected\": false"));
    for sensitive in ["doctor-password-marker", "doctor-wrapping-secret-marker"] {
        assert!(!stdout.contains(sensitive));
        assert!(!stderr.contains(sensitive));
    }
}
