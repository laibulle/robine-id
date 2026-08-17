use robine_id::recovery;
use serde_json::json;
use std::{env, io};

fn main() -> io::Result<()> {
    let mut arguments = env::args().skip(1);
    let count = arguments
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "count must be an integer"))?
        .unwrap_or(10);
    if arguments.next().is_some() || !(1..=16).contains(&count) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: generate_recovery_codes [count from 1 through 16]",
        ));
    }

    let mut codes = Vec::with_capacity(count);
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let code = recovery::generate_code().map_err(io::Error::other)?;
        let hash = recovery::hash_code(&code)
            .ok_or_else(|| io::Error::other("generated recovery code was invalid"))?;
        hashes.push(hash.to_string());
        codes.push(code);
    }

    println!("Recovery codes (display once and store offline):");
    for code in &codes {
        println!("{}", code.as_str());
    }
    println!("\nAdd this field to the configured user:");
    let document = json!({"recovery_code_hashes": hashes});
    println!(
        "{}",
        serde_json::to_string_pretty(&document).map_err(io::Error::other)?
    );
    Ok(())
}
