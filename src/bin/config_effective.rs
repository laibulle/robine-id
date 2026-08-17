use robine_id::Snapshot;
use std::io;

fn main() -> io::Result<()> {
    let snapshot = Snapshot::load().map_err(io::Error::other)?;
    let output = serde_json::to_string_pretty(&snapshot.redacted()).map_err(io::Error::other)?;
    println!("{output}");
    Ok(())
}
