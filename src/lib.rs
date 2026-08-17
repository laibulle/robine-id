#![forbid(unsafe_code)]

pub mod configuration;
pub mod database;
pub mod metrics;
pub mod pairwise;
pub mod protocol;
pub mod recovery;
pub mod tokens;
pub mod totp;
pub mod web;

use std::sync::{
    Arc, Once, RwLock,
    atomic::{AtomicBool, Ordering},
};
use thiserror::Error;
use tracing_subscriber::EnvFilter;

const SIGNING_KEY_ROTATION_CHECK_INTERVAL_SECONDS: u64 = 300;

pub use configuration::{ConfigurationError, Snapshot};

#[derive(Debug, Error)]
pub enum ApplicationLoadError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    #[error(transparent)]
    Database(#[from] database::DatabaseConfigurationError),
}

#[derive(Clone)]
pub struct Application {
    snapshot: Arc<RwLock<Arc<Snapshot>>>,
    database: Option<database::Database>,
    metrics: Arc<metrics::Metrics>,
    accepting_traffic: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationOutcome {
    Activated,
    Unchanged,
}

pub fn initialize_tracing(application: &Application) {
    static INITIALIZE: Once = Once::new();
    let configured_level = application
        .snapshot()
        .configuration
        .telemetry
        .log_level
        .clone()
        .unwrap_or_else(|| "info".to_owned());
    let configured_level = if configured_level == "warning" {
        "warn"
    } else {
        &configured_level
    };
    INITIALIZE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_current_span(true)
            .with_span_list(false)
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("robine_id={configured_level},vercel={configured_level}").into()
            }))
            .try_init();
    });
}

impl Application {
    pub fn load() -> Result<Self, ApplicationLoadError> {
        Self::new(Snapshot::load()?).map_err(Into::into)
    }

    pub fn new(snapshot: Snapshot) -> Result<Self, database::DatabaseConfigurationError> {
        Ok(Self {
            snapshot: Arc::new(RwLock::new(Arc::new(snapshot))),
            database: database::Database::from_env()?,
            metrics: Arc::new(metrics::Metrics::default()),
            accepting_traffic: Arc::new(AtomicBool::new(true)),
        })
    }

    pub fn without_database(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Arc::new(snapshot))),
            database: None,
            metrics: Arc::new(metrics::Metrics::default()),
            accepting_traffic: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        match self.snapshot.read() {
            Ok(active) => active.clone(),
            Err(poisoned) => {
                tracing::error!(
                    event = "configuration_snapshot_lock",
                    outcome = "recovered",
                    "recovered poisoned configuration snapshot read lock"
                );
                poisoned.into_inner().clone()
            }
        }
    }

    pub fn activate_snapshot(&self, snapshot: Snapshot) -> ReconciliationOutcome {
        let mut active = match self.snapshot.write() {
            Ok(active) => active,
            Err(poisoned) => {
                tracing::error!(
                    event = "configuration_snapshot_lock",
                    outcome = "recovered",
                    "recovered poisoned configuration snapshot write lock"
                );
                poisoned.into_inner()
            }
        };
        if active.revision == snapshot.revision {
            ReconciliationOutcome::Unchanged
        } else {
            *active = Arc::new(snapshot);
            ReconciliationOutcome::Activated
        }
    }

    pub fn spawn_configuration_reloader(&self, interval_milliseconds: u64) {
        if std::env::var_os("VERCEL").is_some()
            || std::env::var_os("ROBINE_ID_CONFIG_JSON").is_some()
            || interval_milliseconds == 0
        {
            return;
        }

        let application = self.clone();
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_millis(interval_milliseconds));
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
                            tracing::debug!(
                                event = "configuration_reconciliation",
                                outcome = "unchanged",
                                %revision,
                                "configuration is unchanged"
                            );
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

    pub fn spawn_database_maintenance(&self, interval_seconds: u64) {
        if std::env::var_os("VERCEL").is_some() {
            return;
        }
        let Some(database) = self.database.clone() else {
            return;
        };
        let maintenance_application = self.clone();
        if interval_seconds == 0 {
            return;
        }

        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(interval_seconds));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match database.cleanup_expired_state().await {
                    Ok(()) => tracing::debug!(
                        event = "database_maintenance",
                        outcome = "success",
                        "expired protocol state removed"
                    ),
                    Err(error) => tracing::error!(
                        event = "database_maintenance",
                        outcome = "failed",
                        %error,
                        "expired protocol state cleanup failed"
                    ),
                }
                match maintenance_application.prune_retained_signing_keys().await {
                    Ok(pruned) if pruned > 0 => tracing::info!(
                        event = "signing_key_pruning",
                        outcome = "pruned",
                        pruned,
                        "expired retained signing keys removed"
                    ),
                    Ok(_) => tracing::debug!(
                        event = "signing_key_pruning",
                        outcome = "unchanged",
                        "retained signing keys remain within their verification window"
                    ),
                    Err(error) => tracing::error!(
                        event = "signing_key_pruning",
                        outcome = "failed",
                        %error,
                        "retained signing key cleanup failed"
                    ),
                }
            }
        });
    }

    pub fn spawn_signing_key_rotation(&self) {
        if std::env::var_os("VERCEL").is_some() || self.database.is_none() {
            return;
        }
        let application = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                SIGNING_KEY_ROTATION_CHECK_INTERVAL_SECONDS,
            ));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match application.rotate_due_signing_keys().await {
                    Ok(rotated) if rotated > 0 => tracing::info!(
                        event = "automatic_signing_key_rotation",
                        outcome = "rotated",
                        rotated,
                        "due signing keys rotated"
                    ),
                    Ok(_) => tracing::debug!(
                        event = "automatic_signing_key_rotation",
                        outcome = "unchanged",
                        "signing keys remain inside their configured rotation interval"
                    ),
                    Err(error) => tracing::error!(
                        event = "automatic_signing_key_rotation",
                        outcome = "failed",
                        %error,
                        "automatic signing key rotation failed"
                    ),
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

    pub fn accepting_traffic(&self) -> bool {
        self.accepting_traffic.load(Ordering::Acquire)
    }

    pub fn begin_draining(&self) -> bool {
        self.accepting_traffic.swap(false, Ordering::AcqRel)
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        if let Some(database) = &self.database {
            database.migrate().await?;
            let pruned = self.prune_retained_signing_keys().await?;
            if pruned > 0 {
                tracing::info!(
                    event = "signing_key_pruning",
                    outcome = "pruned",
                    pruned,
                    "expired retained signing keys removed during startup"
                );
            }
        }
        Ok(())
    }

    pub async fn prune_retained_signing_keys(&self) -> Result<u64, sqlx::Error> {
        let Some(database) = &self.database else {
            return Ok(0);
        };
        database.prune_retained_signing_keys().await
    }

    pub async fn rotate_due_signing_keys(&self) -> Result<u64, sqlx::Error> {
        let Some(database) = &self.database else {
            return Ok(0);
        };
        let snapshot = self.snapshot();
        let mut rotated = 0;
        for issuer in snapshot.active_issuers() {
            let Some(interval) = issuer.token_policy.signing_key_rotation_interval else {
                continue;
            };
            let (_, changed) = database
                .rotate_signing_key_if_due(
                    issuer.url.trim_end_matches('/'),
                    interval,
                    issuer.signing_key_retention_seconds(),
                    chrono::Utc::now(),
                )
                .await?;
            rotated += u64::from(changed);
        }
        Ok(rotated)
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
        assert!(application.accepting_traffic());
        assert!(application.begin_draining());
        assert!(!application.begin_draining());
        assert!(!application.accepting_traffic());
        assert_eq!(
            application.activate_snapshot(changed),
            ReconciliationOutcome::Unchanged
        );
    }

    #[test]
    fn recovers_a_poisoned_atomic_snapshot_lock() {
        let initial = Snapshot::load().expect("initial configuration");
        let application = Application::without_database(initial.clone());
        let lock = application.snapshot.clone();
        assert!(
            std::thread::spawn(move || {
                let _active = lock.write().expect("snapshot write lock");
                panic!("poison snapshot lock for recovery coverage");
            })
            .join()
            .is_err()
        );

        assert_eq!(application.snapshot().revision, initial.revision);
        let mut changed = initial;
        changed.revision = "recovered-revision".to_owned();
        assert_eq!(
            application.activate_snapshot(changed),
            ReconciliationOutcome::Activated
        );
        assert_eq!(application.snapshot().revision, "recovered-revision");
    }
}
