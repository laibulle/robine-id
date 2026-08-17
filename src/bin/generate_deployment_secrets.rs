use std::{env, io};

fn main() -> io::Result<()> {
    if env::args_os().nth(1).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: generate_deployment_secrets",
        ));
    }

    let database_password =
        robine_id::secrets::generate_database_password().map_err(io::Error::other)?;
    let encryption_secret =
        robine_id::secrets::generate_key_encryption_secret().map_err(io::Error::other)?;
    println!("# Store these independent values once; do not commit this output.");
    println!("POSTGRES_PASSWORD={}", database_password.as_str());
    println!("KEY_ENCRYPTION_SECRET={}", encryption_secret.as_str());
    Ok(())
}
