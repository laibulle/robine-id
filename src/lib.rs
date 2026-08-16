#![forbid(unsafe_code)]

pub mod configuration;
pub mod protocol;
pub mod web;

use std::sync::Arc;

pub use configuration::{ConfigurationError, Snapshot};

#[derive(Clone)]
pub struct Application {
    snapshot: Arc<Snapshot>,
}

impl Application {
    pub fn load() -> Result<Self, ConfigurationError> {
        Snapshot::load().map(Self::new)
    }

    pub fn new(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Arc::new(snapshot),
        }
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
}
