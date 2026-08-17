use robine_id::{Application, initialize_tracing};
use std::{env, io};

#[tokio::main]
async fn main() -> io::Result<()> {
    if env::args().nth(1).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: reencrypt_keys",
        ));
    }

    let application = Application::load().map_err(|error| io::Error::other(error.to_string()))?;
    initialize_tracing(&application);
    let database = application
        .database()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "DATABASE_URL is required"))?;
    database.migrate().await.map_err(io::Error::other)?;
    let reencrypted = database
        .reencrypt_signing_keys()
        .await
        .map_err(io::Error::other)?;
    tracing::info!(
        event = "signing_key_reencryption",
        outcome = "completed",
        active = reencrypted.active,
        retained = reencrypted.retained,
        "operator signing key re-encryption completed"
    );
    println!(
        "reencrypted {} active and {} retained signing keys",
        reencrypted.active, reencrypted.retained
    );
    Ok(())
}
