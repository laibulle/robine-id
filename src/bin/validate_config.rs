use robine_id::Snapshot;
use std::io;

fn main() -> io::Result<()> {
    let snapshot = Snapshot::load().map_err(io::Error::other)?;
    println!(
        "configuration is valid: revision={} issuers={} clients={} users={}",
        snapshot.revision,
        snapshot.configuration.issuers.len(),
        snapshot.configuration.clients.len(),
        snapshot.configuration.users.len()
    );
    Ok(())
}
