#![forbid(unsafe_code)]

pub mod configuration;
pub mod database;
pub mod protocol;
pub mod tokens;
pub mod web;

use std::sync::Arc;

pub use configuration::{ConfigurationError, Snapshot};

#[derive(Clone)]
pub struct Application {
    snapshot: Arc<Snapshot>,
    database: Option<database::Database>,
}

impl Application {
    pub fn load() -> Result<Self, ConfigurationError> {
        Snapshot::load().map(Self::new)
    }

    pub fn new(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Arc::new(snapshot),
            database: database::Database::from_env(),
        }
    }

    #[cfg(test)]
    pub fn without_database(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Arc::new(snapshot),
            database: None,
        }
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn database(&self) -> Option<&database::Database> {
        self.database.as_ref()
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        if let Some(database) = &self.database {
            database.migrate().await?;
        }
        Ok(())
    }
}
