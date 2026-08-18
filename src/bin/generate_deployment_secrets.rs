use std::{env, ffi::OsStr, io, path::PathBuf};

fn main() -> io::Result<()> {
    let mut arguments = env::args_os().skip(1);
    match arguments.next() {
        None => print_assignments(),
        Some(argument) if argument == OsStr::new("--directory") => {
            let directory = arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(usage_error)?;
            if arguments.next().is_some() {
                return Err(usage_error());
            }
            robine_id::secrets::create_deployment_secret_files(&directory)
                .map_err(|error| io::Error::other(error.to_string()))?;
            println!(
                "Created postgres_password, key_encryption_secret, and oauth2_proxy_client_secret without replacing existing files."
            );
            Ok(())
        }
        Some(_) => Err(usage_error()),
    }
}

fn print_assignments() -> io::Result<()> {
    let database_password =
        robine_id::secrets::generate_database_password().map_err(io::Error::other)?;
    let encryption_secret =
        robine_id::secrets::generate_key_encryption_secret().map_err(io::Error::other)?;
    let oauth2_proxy_client_secret =
        robine_id::secrets::generate_oauth2_proxy_client_secret().map_err(io::Error::other)?;
    println!("# Store these independent values once; do not commit this output.");
    println!("POSTGRES_PASSWORD={}", database_password.as_str());
    println!("KEY_ENCRYPTION_SECRET={}", encryption_secret.as_str());
    println!(
        "OAUTH2_PROXY_CLIENT_SECRET={}",
        oauth2_proxy_client_secret.as_str()
    );
    Ok(())
}

fn usage_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: generate_deployment_secrets [--directory PATH]",
    )
}
