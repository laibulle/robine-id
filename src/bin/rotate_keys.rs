use robine_id::Application;
use std::{env, io};

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut arguments = env::args().skip(1);
    let issuer_id = arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: rotate_keys <issuer-id> <rotation-id>",
        )
    })?;
    let rotation_id = arguments.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: rotate_keys <issuer-id> <rotation-id>",
        )
    })?;
    if arguments.next().is_some() || rotation_id.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: rotate_keys <issuer-id> <rotation-id>",
        ));
    }

    let application = Application::load().map_err(io::Error::other)?;
    application.migrate().await.map_err(io::Error::other)?;
    let issuer = application
        .snapshot()
        .issuer(&issuer_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown issuer"))?;
    let database = application
        .database()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "DATABASE_URL is required"))?;
    let (key, changed) = database
        .rotate_signing_key(issuer.url.trim_end_matches('/'), &rotation_id)
        .await
        .map_err(io::Error::other)?;
    let outcome = if changed { "rotated" } else { "unchanged" };
    println!("{outcome} issuer {issuer_id} at key {}", key.kid);
    Ok(())
}
