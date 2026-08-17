use robine_id::{Application, ReconciliationOutcome, Snapshot};
use std::{env, io, path::Path};

fn main() -> io::Result<()> {
    let active = Snapshot::load().map_err(io::Error::other)?;
    let desired = match env::args().nth(1) {
        Some(path) => Snapshot::load_path(Path::new(&path)).map_err(io::Error::other)?,
        None => active.clone(),
    };
    let revision = desired.revision.clone();
    let application = Application::without_database(active);
    let outcome = application.activate_snapshot(desired);
    let outcome = match outcome {
        ReconciliationOutcome::Activated => "activated",
        ReconciliationOutcome::Unchanged => "unchanged",
    };
    println!("{outcome}\t{revision}");
    Ok(())
}
