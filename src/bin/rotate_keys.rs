use robine_id::{Application, initialize_tracing};
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

    let application = Application::load().map_err(|error| io::Error::other(error.to_string()))?;
    initialize_tracing(&application);
    application.migrate().await.map_err(io::Error::other)?;
    let snapshot = application.snapshot();
    let issuer = snapshot
        .issuer(&issuer_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown issuer"))?;
    let database = application
        .database()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "DATABASE_URL is required"))?;
    let (key, changed) = match database
        .rotate_signing_key(
            issuer.url.trim_end_matches('/'),
            &rotation_id,
            issuer.signing_key_retention_seconds(),
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(
                event = "signing_key_rotation",
                outcome = "failed",
                issuer_id,
                reason = "rotation_failed",
                "signing key rotation failed"
            );
            return Err(io::Error::other(error));
        }
    };
    let outcome = if changed { "rotated" } else { "unchanged" };
    println!("{outcome} issuer {issuer_id} at key {}", key.kid);
    Ok(())
}
