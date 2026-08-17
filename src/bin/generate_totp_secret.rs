use std::{env, io};

fn main() -> io::Result<()> {
    if env::args_os().nth(1).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: generate_totp_secret",
        ));
    }
    let secret = robine_id::totp::generate_secret().map_err(io::Error::other)?;
    println!("TOTP secret (store in the deployment secret manager):");
    println!("{}", secret.as_str());
    Ok(())
}
