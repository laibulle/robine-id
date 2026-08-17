#![forbid(unsafe_code)]

pub mod configuration;
pub mod database;
pub mod metrics;
pub mod pairwise;
pub mod protocol;
pub mod provisioning;
pub mod recovery;
pub mod secret_source;
pub mod secrets;
pub mod tokens;
pub mod totp;
pub mod web;

use std::sync::{
    Arc, Mutex, Once, RwLock,
    atomic::{AtomicBool, Ordering},
};
use thiserror::Error;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

const SIGNING_KEY_ROTATION_CHECK_INTERVAL_SECONDS: u64 = 300;
const MINIMUM_METRICS_BEARER_TOKEN_BYTES: usize = 32;
const MAXIMUM_METRICS_BEARER_TOKEN_BYTES: usize = 256;

pub use configuration::{ConfigurationError, Snapshot};

#[derive(Debug, Error)]
pub enum ApplicationLoadError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    #[error(transparent)]
    Database(#[from] database::DatabaseConfigurationError),
    #[error(transparent)]
    Metrics(#[from] MetricsConfigurationError),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MetricsConfigurationError {
    #[error(transparent)]
    SecretSource(#[from] secret_source::SecretSourceError),
    #[error(
        "METRICS_BEARER_TOKEN must contain between 32 and 256 URL-safe ASCII characters"
    )]
    InvalidToken,
}

#[derive(Clone)]
pub struct Application {
    snapshot: Arc<RwLock<Arc<Snapshot>>>,
    database: Option<database::Database>,
    metrics: Arc<metrics::Metrics>,
    metrics_bearer_token: Option<Arc<Zeroizing<String>>>,
    accepting_traffic: Arc<AtomicBool>,
    last_configuration_error: Arc<Mutex<Option<String>>>,
    configuration_reload_lock: Arc<tokio::sync::Mutex<()>>,
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
        Self::new(Snapshot::load()?)
    }

    pub fn new(snapshot: Snapshot) -> Result<Self, ApplicationLoadError> {
        let metrics_bearer_token = metrics_bearer_token_from_environment()?;
        Ok(Self {
            snapshot: Arc::new(RwLock::new(Arc::new(snapshot))),
            database: database::Database::from_env()?,
            metrics: Arc::new(metrics::Metrics::default()),
            metrics_bearer_token: metrics_bearer_token.map(Arc::new),
            accepting_traffic: Arc::new(AtomicBool::new(true)),
            last_configuration_error: Arc::new(Mutex::new(None)),
            configuration_reload_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn without_database(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Arc::new(snapshot))),
            database: None,
            metrics: Arc::new(metrics::Metrics::default()),
            metrics_bearer_token: None,
            accepting_traffic: Arc::new(AtomicBool::new(true)),
            last_configuration_error: Arc::new(Mutex::new(None)),
            configuration_reload_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub fn without_database_with_metrics_bearer_token(
        snapshot: Snapshot,
        token: Zeroizing<String>,
    ) -> Result<Self, MetricsConfigurationError> {
        validate_metrics_bearer_token(&token)?;
        let mut application = Self::without_database(snapshot);
        application.metrics_bearer_token = Some(Arc::new(token));
        Ok(application)
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
            loop {
                ticker.tick().await;
                let _ = application.reload_configuration("poll").await;
            }
        });
    }

    pub async fn reload_configuration(
        &self,
        trigger: &'static str,
    ) -> Option<ReconciliationOutcome> {
        self.reload_configuration_with(trigger, Snapshot::load)
            .await
    }

    async fn reload_configuration_with<F>(
        &self,
        trigger: &'static str,
        loader: F,
    ) -> Option<ReconciliationOutcome>
    where
        F: FnOnce() -> Result<Snapshot, ConfigurationError> + Send + 'static,
    {
        let _reload_guard = self.configuration_reload_lock.lock().await;
        match tokio::task::spawn_blocking(loader).await {
            Ok(Ok(snapshot)) => {
                self.clear_configuration_reload_error();
                let revision = snapshot.revision.clone();
                let outcome = self.activate_snapshot(snapshot);
                if outcome == ReconciliationOutcome::Activated {
                    self.metrics.configuration_activated();
                    tracing::info!(
                        event = "configuration_reconciliation",
                        outcome = "activated",
                        trigger,
                        %revision,
                        "configuration activated"
                    );
                } else {
                    self.metrics.configuration_unchanged();
                    tracing::debug!(
                        event = "configuration_reconciliation",
                        outcome = "unchanged",
                        trigger,
                        %revision,
                        "configuration is unchanged"
                    );
                }
                Some(outcome)
            }
            Ok(Err(error)) => {
                self.record_configuration_reload_error(
                    trigger,
                    error.to_string(),
                    "configuration reload rejected; retaining active revision",
                );
                None
            }
            Err(error) => {
                self.record_configuration_reload_error(
                    trigger,
                    error.to_string(),
                    "configuration reload task failed; retaining active revision",
                );
                None
            }
        }
    }

    fn clear_configuration_reload_error(&self) {
        let mut last_error = match self.last_configuration_error.lock() {
            Ok(last_error) => last_error,
            Err(poisoned) => {
                tracing::error!(
                    event = "configuration_reconciliation",
                    outcome = "lock_recovered",
                    "recovered poisoned configuration reload state lock"
                );
                poisoned.into_inner()
            }
        };
        *last_error = None;
    }

    fn record_configuration_reload_error(
        &self,
        trigger: &'static str,
        diagnostic: String,
        message: &'static str,
    ) {
        let mut last_error = match self.last_configuration_error.lock() {
            Ok(last_error) => last_error,
            Err(poisoned) => {
                tracing::error!(
                    event = "configuration_reconciliation",
                    outcome = "lock_recovered",
                    "recovered poisoned configuration reload state lock"
                );
                poisoned.into_inner()
            }
        };
        if last_error.as_deref() == Some(diagnostic.as_str()) {
            return;
        }
        self.metrics.configuration_failed();
        tracing::error!(
            event = "configuration_reconciliation",
            outcome = "failed",
            trigger,
            diagnostic = %diagnostic,
            detail = message,
            "configuration reload failed; retaining active revision"
        );
        *last_error = Some(diagnostic);
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

    pub fn metrics_bearer_token(&self) -> Option<&str> {
        self.metrics_bearer_token
            .as_deref()
            .map(|token| token.as_str())
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

fn metrics_bearer_token_from_environment(
) -> Result<Option<Zeroizing<String>>, MetricsConfigurationError> {
    let token = secret_source::from_environment("METRICS_BEARER_TOKEN")?;
    if let Some(token) = token.as_deref() {
        validate_metrics_bearer_token(token)?;
    }
    Ok(token)
}

fn validate_metrics_bearer_token(token: &str) -> Result<(), MetricsConfigurationError> {
    if !(MINIMUM_METRICS_BEARER_TOKEN_BYTES..=MAXIMUM_METRICS_BEARER_TOKEN_BYTES)
        .contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(MetricsConfigurationError::InvalidToken);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_bearer_tokens_are_bounded_and_header_safe() {
        for token in [
            "",
            "short",
            &"a".repeat(MAXIMUM_METRICS_BEARER_TOKEN_BYTES + 1),
            "contains spaces despite being long enough",
            "contains.a.dot.despite.being.long.enough",
            "éééééééééééééééééééééééééééééééé",
        ] {
            assert_eq!(
                validate_metrics_bearer_token(token),
                Err(MetricsConfigurationError::InvalidToken)
            );
        }
        assert!(validate_metrics_bearer_token(&"a".repeat(32)).is_ok());
        assert!(
            validate_metrics_bearer_token(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            )
            .is_ok()
        );
    }

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

    #[tokio::test]
    async fn reload_pipeline_activates_valid_snapshots_and_deduplicates_failures() {
        let initial = Snapshot::load().expect("initial configuration");
        let application = Application::without_database(initial.clone());
        let mut changed = initial.clone();
        changed.revision = "signal-revision".to_owned();

        assert_eq!(
            application
                .reload_configuration_with("test", move || Ok(changed))
                .await,
            Some(ReconciliationOutcome::Activated)
        );
        assert_eq!(application.snapshot().revision, "signal-revision");

        for _ in 0..2 {
            assert_eq!(
                application
                    .reload_configuration_with("test", || {
                        Err(ConfigurationError::Invalid(
                            "bounded test reload failure".to_owned(),
                        ))
                    })
                    .await,
                None
            );
        }
        let metrics = application.metrics().render("signal-revision", true);
        assert!(
            metrics
                .contains("robine_id_configuration_reconciliation_total{outcome=\"activated\"} 1")
        );
        assert!(
            metrics.contains("robine_id_configuration_reconciliation_total{outcome=\"failed\"} 1")
        );

        let unchanged = application.snapshot().as_ref().clone();
        assert_eq!(
            application
                .reload_configuration_with("test", move || Ok(unchanged))
                .await,
            Some(ReconciliationOutcome::Unchanged)
        );
        assert_eq!(
            application
                .reload_configuration_with("test", || {
                    Err(ConfigurationError::Invalid(
                        "bounded test reload failure".to_owned(),
                    ))
                })
                .await,
            None
        );
        let metrics = application.metrics().render("signal-revision", true);
        assert!(
            metrics
                .contains("robine_id_configuration_reconciliation_total{outcome=\"unchanged\"} 1")
        );
        assert!(
            metrics.contains("robine_id_configuration_reconciliation_total{outcome=\"failed\"} 2")
        );
    }

    #[tokio::test]
    async fn concurrent_reload_triggers_cannot_reactivate_an_older_snapshot() {
        let initial = Snapshot::load().expect("initial configuration");
        let application = Application::without_database(initial.clone());
        let mut older = initial.clone();
        older.revision = "older-candidate".to_owned();
        let mut newer = initial;
        newer.revision = "newer-candidate".to_owned();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = tokio::sync::oneshot::channel();

        let older_application = application.clone();
        let older_reload = tokio::spawn(async move {
            older_application
                .reload_configuration_with("poll", move || {
                    let _ = started_sender.send(());
                    let _ = release_receiver.blocking_recv();
                    Ok(older)
                })
                .await
        });
        started_receiver.await.expect("older loader started");
        assert!(application.configuration_reload_lock.try_lock().is_err());

        let newer_application = application.clone();
        let newer_reload = tokio::spawn(async move {
            newer_application
                .reload_configuration_with("SIGHUP", move || Ok(newer))
                .await
        });
        release_sender.send(()).expect("release older loader");

        assert_eq!(
            older_reload.await.expect("older reload task"),
            Some(ReconciliationOutcome::Activated)
        );
        assert_eq!(
            newer_reload.await.expect("newer reload task"),
            Some(ReconciliationOutcome::Activated)
        );
        assert_eq!(application.snapshot().revision, "newer-candidate");
    }
}
