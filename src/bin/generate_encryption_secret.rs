use std::{env, io};

fn main() -> io::Result<()> {
    if env::args_os().nth(1).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: generate_encryption_secret",
        ));
    }

    let secret = robine_id::secrets::generate_key_encryption_secret().map_err(io::Error::other)?;
    println!("KEY_ENCRYPTION_SECRET (store this output once in the deployment secret manager):");
    println!("KEY_ENCRYPTION_SECRET={}", secret.as_str());
    Ok(())
}
