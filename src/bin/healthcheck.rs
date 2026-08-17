use std::{
    env,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    process::ExitCode,
    time::Duration,
};

const DEFAULT_PORT: u16 = 4001;
const MAX_RESPONSE_BYTES: u64 = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(3);

fn main() -> ExitCode {
    match configured_port().and_then(check_readiness) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Robine ID readiness check failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn configured_port() -> Result<u16, String> {
    let value = match env::var("PORT") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(DEFAULT_PORT),
        Err(env::VarError::NotUnicode(_)) => {
            return Err("PORT must contain valid Unicode".to_owned());
        }
    };
    let port = value
        .parse::<u16>()
        .map_err(|_| "PORT must be an integer between 1 and 65535".to_owned())?;
    if port == 0 {
        return Err("PORT must be between 1 and 65535".to_owned());
    }
    Ok(port)
}

fn check_readiness(port: u16) -> Result<(), String> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut stream = TcpStream::connect_timeout(&address.into(), TIMEOUT)
        .map_err(|error| safe_io_error("cannot connect", error))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|error| safe_io_error("cannot set read timeout", error))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|error| safe_io_error("cannot set write timeout", error))?;
    stream
        .write_all(
            b"GET /health/ready HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        )
        .map_err(|error| safe_io_error("cannot send request", error))?;

    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut response)
        .map_err(|error| safe_io_error("cannot read response", error))?;
    validate_response(&response)
}

fn validate_response(response: &[u8]) -> Result<(), String> {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err("server returned a malformed HTTP response".to_owned());
    };
    let headers = &response[..header_end];
    if !headers.starts_with(b"HTTP/1.1 200 ") {
        return Err("server is not ready".to_owned());
    }
    let body = &response[header_end + 4..];
    let document: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| "server returned malformed readiness JSON".to_owned())?;
    if document.get("status").and_then(|status| status.as_str()) != Some("ready") {
        return Err("server is not ready".to_owned());
    }
    Ok(())
}

fn safe_io_error(context: &str, error: io::Error) -> String {
    format!("{context}: {}", error.kind())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_a_ready_success_response() {
        assert!(
            validate_response(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"status\":\"ready\",\"revision\":\"abc\"}"
            )
            .is_ok()
        );
        assert!(
            validate_response(
                b"HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\n\r\n{\"status\":\"not_ready\"}"
            )
            .is_err()
        );
        assert!(
            validate_response(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"status\":\"not_ready\"}"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_truncated_or_malformed_responses() {
        assert!(validate_response(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(validate_response(b"HTTP/1.1 200 OK\r\n\r\nnot-json").is_err());
    }
}
