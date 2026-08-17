#![forbid(unsafe_code)]

pub mod configuration;
pub mod database;
pub mod metrics;
pub mod protocol;
pub mod tokens;
pub mod web;

use std::sync::{Arc, RwLock};

pub use configuration::{ConfigurationError, Snapshot};

#[derive(Clone)]
pub struct Application {
    snapshot: Arc<RwLock<Arc<Snapshot>>>,
    database: Option<database::Database>,
    metrics: Arc<metrics::Metrics>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationOutcome {
    Activated,
    Unchanged,
}

impl Application {
    pub fn load() -> Result<Self, ConfigurationError> {
        Snapshot::load().map(Self::new)
    }

    pub fn new(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Arc::new(snapshot))),
            database: database::Database::from_env(),
            metrics: Arc::new(metrics::Metrics::default()),
        }
    }

    pub fn without_database(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Arc::new(snapshot))),
            database: None,
            metrics: Arc::new(metrics::Metrics::default()),
        }
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot
            .read()
            .expect("configuration snapshot lock poisoned")
            .clone()
    }

    pub fn activate_snapshot(&self, snapshot: Snapshot) -> ReconciliationOutcome {
        let mut active = self
            .snapshot
            .write()
            .expect("configuration snapshot lock poisoned");
        if active.revision == snapshot.revision {
            ReconciliationOutcome::Unchanged
        } else {
            *active = Arc::new(snapshot);
            ReconciliationOutcome::Activated
        }
    }

    pub fn spawn_configuration_reloader(&self) {
        if std::env::var_os("VERCEL").is_some()
            || std::env::var_os("ROBINE_ID_CONFIG_JSON").is_some()
        {
            return;
        }
        let interval = std::env::var("ROBINE_ID_RELOAD_INTERVAL")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1_000);
        if interval == 0 {
            return;
        }

        let application = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(interval));
            ticker.tick().await;
            let mut last_error = None;
            loop {
                ticker.tick().await;
                let loaded = tokio::task::spawn_blocking(Snapshot::load).await;
                match loaded {
                    Ok(Ok(snapshot)) => {
                        let revision = snapshot.revision.clone();
                        let outcome = application.activate_snapshot(snapshot);
                        if outcome == ReconciliationOutcome::Activated {
                            application.metrics.configuration_activated();
                            tracing::info!(
                                event = "configuration_reconciliation",
                                outcome = "activated",
                                %revision,
                                "configuration activated"
                            );
                        } else {
                            application.metrics.configuration_unchanged();
                        }
                        last_error = None;
                    }
                    Ok(Err(error)) => {
                        let diagnostic = error.to_string();
                        if last_error.as_deref() != Some(diagnostic.as_str()) {
                            application.metrics.configuration_failed();
                            tracing::error!(
                                event = "configuration_reconciliation",
                                outcome = "failed",
                                diagnostic = %diagnostic,
                                "configuration reload rejected; retaining active revision"
                            );
                            last_error = Some(diagnostic);
                        }
                    }
                    Err(error) => {
                        let diagnostic = error.to_string();
                        if last_error.as_deref() != Some(diagnostic.as_str()) {
                            application.metrics.configuration_failed();
                            tracing::error!(
                                event = "configuration_reconciliation",
                                outcome = "failed",
                                diagnostic = %diagnostic,
                                "configuration reload task failed; retaining active revision"
                            );
                            last_error = Some(diagnostic);
                        }
                    }
                }
            }
        });
    }

    pub fn database(&self) -> Option<&database::Database> {
        self.database.as_ref()
    }

    pub fn metrics(&self) -> &metrics::Metrics {
        &self.metrics
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        if let Some(database) = &self.database {
            database.migrate().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activates_a_new_configuration_revision_atomically() {
        let initial = Snapshot::load().expect("initial configuration");
        let mut changed = initial.clone();
        changed.revision = "new-revision".to_owned();
        let application = Application::without_database(initial);

        assert_eq!(
            application.activate_snapshot(changed.clone()),
            ReconciliationOutcome::Activated
        );
        assert_eq!(application.snapshot().revision, "new-revision");
        assert_eq!(
            application.activate_snapshot(changed),
            ReconciliationOutcome::Unchanged
        );
    }
}
