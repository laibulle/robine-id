use robine_id::{Application, Snapshot};
use serde::Serialize;
use std::{io, process::ExitCode};

#[derive(Debug, Serialize)]
struct DoctorReport {
    status: &'static str,
    configuration: ConfigurationReport,
    database: DatabaseReport,
}

#[derive(Debug, Serialize)]
struct ConfigurationReport {
    revision: String,
    active_issuers: usize,
    active_clients: usize,
    active_users: usize,
}

#[derive(Debug, Serialize)]
struct DatabaseReport {
    connected: bool,
    migrations: Option<MigrationReport>,
    signing_keys: Option<SigningKeyReport>,
}

#[derive(Debug, Serialize)]
struct MigrationReport {
    current: bool,
    applied: usize,
    expected: usize,
    failed: usize,
}

#[derive(Debug, Serialize)]
struct SigningKeyReport {
    active: usize,
    retained: usize,
    configured_active_issuers: usize,
    missing_for_configured_issuers: usize,
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        eprintln!("usage: robine-id-doctor");
        return ExitCode::FAILURE;
    }
    let application = match Application::load() {
        Ok(application) => application,
        Err(error) => {
            eprintln!("Robine ID diagnostic initialization failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let configuration = configuration_report(&application.snapshot());
    let Some(database) = application.database() else {
        eprintln!("Robine ID diagnostic initialization failed: DATABASE_URL is required");
        return ExitCode::FAILURE;
    };

    let mut report = DoctorReport {
        status: "not_ready",
        configuration,
        database: DatabaseReport {
            connected: database.healthy().await,
            migrations: None,
            signing_keys: None,
        },
    };
    if report.database.connected
        && let Ok(migrations) = database.migration_status().await
    {
        let migrations_current = migrations.current;
        report.database.migrations = Some(MigrationReport {
            current: migrations.current,
            applied: migrations.applied,
            expected: migrations.expected,
            failed: migrations.failed,
        });
        if migrations_current && let Ok(inventory) = database.signing_key_inventory().await {
            let snapshot = application.snapshot();
            let issuers = snapshot
                .active_issuers()
                .map(|issuer| issuer.url.trim_end_matches('/').to_owned())
                .collect::<Vec<_>>();
            let mut present = 0;
            let mut inventory_readable = true;
            for issuer in &issuers {
                match database.has_signing_key(issuer).await {
                    Ok(true) => present += 1,
                    Ok(false) => {}
                    Err(_) => inventory_readable = false,
                }
            }
            if inventory_readable {
                report.database.signing_keys = Some(SigningKeyReport {
                    active: inventory.active,
                    retained: inventory.retained,
                    configured_active_issuers: issuers.len(),
                    missing_for_configured_issuers: issuers.len().saturating_sub(present),
                });
                report.status = "ready";
            }
        }
    }

    match write_report(&report) {
        Ok(()) if report.status == "ready" => ExitCode::SUCCESS,
        Ok(()) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("Robine ID diagnostic output failed: {}", error.kind());
            ExitCode::FAILURE
        }
    }
}

fn configuration_report(snapshot: &Snapshot) -> ConfigurationReport {
    ConfigurationReport {
        revision: snapshot.revision.clone(),
        active_issuers: snapshot.active_issuers().count(),
        active_clients: snapshot
            .configuration
            .clients
            .iter()
            .filter(|client| client.enabled)
            .count(),
        active_users: snapshot
            .configuration
            .users
            .iter()
            .filter(|user| user.enabled)
            .count(),
    }
}

fn write_report(report: &DoctorReport) -> io::Result<()> {
    serde_json::to_writer_pretty(io::stdout().lock(), report).map_err(io::Error::other)?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_summary_counts_only_active_objects() {
        let mut snapshot = Snapshot::load().expect("development configuration");
        snapshot.configuration.issuers[0].enabled = false;
        snapshot.configuration.clients[0].enabled = false;
        snapshot.configuration.users[0].enabled = false;

        let report = configuration_report(&snapshot);
        assert_eq!(report.active_issuers, 0);
        assert_eq!(
            report.active_clients,
            snapshot.configuration.clients.len() - 1
        );
        assert_eq!(report.active_users, snapshot.configuration.users.len() - 1);
    }

    #[test]
    fn report_serialization_is_bounded_and_contains_no_database_diagnostics() {
        let report = DoctorReport {
            status: "not_ready",
            configuration: ConfigurationReport {
                revision: "revision-123".to_owned(),
                active_issuers: 1,
                active_clients: 2,
                active_users: 3,
            },
            database: DatabaseReport {
                connected: false,
                migrations: None,
                signing_keys: None,
            },
        };
        let encoded = serde_json::to_string(&report).expect("diagnostic JSON");
        assert!(encoded.contains("\"status\":\"not_ready\""));
        assert!(encoded.contains("\"connected\":false"));
        assert!(!encoded.contains("DATABASE_URL"));
        assert!(!encoded.contains("password"));
    }
}
