use std::{env, io};

fn main() -> io::Result<()> {
    if env::args_os().nth(1).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: generate_metrics_bearer_token",
        ));
    }

    let token = robine_id::secrets::generate_metrics_bearer_token().map_err(io::Error::other)?;
    println!("METRICS_BEARER_TOKEN={}", token.as_str());
    Ok(())
}
