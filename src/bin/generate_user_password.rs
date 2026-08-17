use robine_id::provisioning::{self, DEFAULT_BCRYPT_COST};
use serde_json::json;
use std::{env, io};

fn main() -> io::Result<()> {
    let mut arguments = env::args().skip(1);
    let cost = arguments
        .next()
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cost must be an integer"))?
        .unwrap_or(DEFAULT_BCRYPT_COST);
    if arguments.next().is_some() || !(10..=16).contains(&cost) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: generate_user_password [bcrypt cost from 10 through 16]",
        ));
    }

    let password = provisioning::generate_initial_password().map_err(io::Error::other)?;
    let hash = provisioning::hash_password(&password, cost).map_err(io::Error::other)?;

    println!("Initial password (display once and deliver securely):");
    println!("{}", password.as_str());
    println!("\nAdd this field to the configured user:");
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"password_hash": hash.as_str()}))
            .map_err(io::Error::other)?
    );
    Ok(())
}
