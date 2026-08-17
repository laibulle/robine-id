use robine_id::{Application, ReconciliationOutcome, Snapshot, initialize_tracing};
use std::{env, io, path::Path};

fn main() -> io::Result<()> {
    let active = Snapshot::load().map_err(io::Error::other)?;
    let desired = match env::args().nth(1) {
        Some(path) => Snapshot::load_path(Path::new(&path)).map_err(io::Error::other)?,
        None => active.clone(),
    };
    let revision = desired.revision.clone();
    let application = Application::without_database(active);
    initialize_tracing(&application);
    let outcome = application.activate_snapshot(desired);
    let outcome = match outcome {
        ReconciliationOutcome::Activated => "activated",
        ReconciliationOutcome::Unchanged => "unchanged",
    };
    tracing::info!(
        event = "configuration_reconciliation",
        outcome,
        %revision,
        "configuration command completed"
    );
    println!("{outcome}\t{revision}");
    Ok(())
}
