use actix_web::{App, HttpServer, web};
use robine_id::{Application, initialize_tracing, metrics::HttpMethodClass, web as robine_web};
use std::time::{Duration, Instant};
use std::{env, io};
use tracing::Instrument;

const DEFAULT_DRAIN_DELAY_MILLISECONDS: u64 = 3_000;
const MAX_DRAIN_DELAY_MILLISECONDS: u64 = 300_000;
const DEFAULT_SHUTDOWN_TIMEOUT_SECONDS: u64 = 10;
const MAX_SHUTDOWN_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_RELOAD_INTERVAL_MILLISECONDS: u64 = 1_000;
const MIN_RELOAD_INTERVAL_MILLISECONDS: u64 = 100;
const MAX_RELOAD_INTERVAL_MILLISECONDS: u64 = 60_000;
const DEFAULT_DATABASE_CLEANUP_INTERVAL_SECONDS: u64 = 3_600;
const MIN_DATABASE_CLEANUP_INTERVAL_SECONDS: u64 = 60;
const MAX_DATABASE_CLEANUP_INTERVAL_SECONDS: u64 = 86_400;

#[derive(Debug, PartialEq, Eq)]
struct ServerSettings {
    host: String,
    port: u16,
    reload_interval_milliseconds: u64,
    database_cleanup_interval_seconds: u64,
    drain_delay_milliseconds: u64,
    shutdown_timeout_seconds: u64,
    trust_proxy_headers: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ServerEnvironment {
    host: Option<String>,
    port: Option<String>,
    reload_interval: Option<String>,
    database_cleanup_interval: Option<String>,
    drain_delay_milliseconds: Option<String>,
    shutdown_timeout_seconds: Option<String>,
    trust_proxy_headers: Option<String>,
}

impl ServerEnvironment {
    fn read() -> io::Result<Self> {
        Ok(Self {
            host: environment_value("HOST")?,
            port: environment_value("PORT")?,
            reload_interval: environment_value("ROBINE_ID_RELOAD_INTERVAL")?,
            database_cleanup_interval: environment_value("DATABASE_CLEANUP_INTERVAL")?,
            drain_delay_milliseconds: environment_value("DRAIN_DELAY_MILLISECONDS")?,
            shutdown_timeout_seconds: environment_value("SHUTDOWN_TIMEOUT_SECONDS")?,
            trust_proxy_headers: environment_value("TRUST_PROXY_HEADERS")?,
        })
    }

    fn build(&self) -> io::Result<ServerSettings> {
        let host = self.host.clone().unwrap_or_else(|| "127.0.0.1".to_owned());
        if host.is_empty() {
            return Err(invalid_setting("HOST", "must not be empty"));
        }

        Ok(ServerSettings {
            host,
            port: parse_port(self.port.as_deref())?,
            reload_interval_milliseconds: parse_disableable_interval(
                "ROBINE_ID_RELOAD_INTERVAL",
                self.reload_interval.as_deref(),
                DEFAULT_RELOAD_INTERVAL_MILLISECONDS,
                MIN_RELOAD_INTERVAL_MILLISECONDS,
                MAX_RELOAD_INTERVAL_MILLISECONDS,
            )?,
            database_cleanup_interval_seconds: parse_disableable_interval(
                "DATABASE_CLEANUP_INTERVAL",
                self.database_cleanup_interval.as_deref(),
                DEFAULT_DATABASE_CLEANUP_INTERVAL_SECONDS,
                MIN_DATABASE_CLEANUP_INTERVAL_SECONDS,
                MAX_DATABASE_CLEANUP_INTERVAL_SECONDS,
            )?,
            drain_delay_milliseconds: parse_bounded_integer(
                "DRAIN_DELAY_MILLISECONDS",
                self.drain_delay_milliseconds.as_deref(),
                DEFAULT_DRAIN_DELAY_MILLISECONDS,
                0,
                MAX_DRAIN_DELAY_MILLISECONDS,
            )?,
            shutdown_timeout_seconds: parse_bounded_integer(
                "SHUTDOWN_TIMEOUT_SECONDS",
                self.shutdown_timeout_seconds.as_deref(),
                DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
                1,
                MAX_SHUTDOWN_TIMEOUT_SECONDS,
            )?,
            trust_proxy_headers: parse_boolean(
                "TRUST_PROXY_HEADERS",
                self.trust_proxy_headers.as_deref(),
                false,
            )?,
        })
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    let settings = ServerEnvironment::read()?.build()?;
    let application = Application::load().map_err(|error| io::Error::other(error.to_string()))?;
    initialize_tracing(&application);

    application.migrate().await.map_err(io::Error::other)?;
    application
        .rotate_due_signing_keys()
        .await
        .map_err(io::Error::other)?;
    application.spawn_configuration_reloader(settings.reload_interval_milliseconds);
    spawn_configuration_reload_signal(application.clone());
    application.spawn_database_maintenance(settings.database_cleanup_interval_seconds);
    application.spawn_signing_key_rotation();
    let drain_delay_milliseconds = settings.drain_delay_milliseconds;
    let shutdown_timeout_seconds = settings.shutdown_timeout_seconds;

    tracing::info!(
        host = %settings.host,
        port = settings.port,
        reload_interval_milliseconds = settings.reload_interval_milliseconds,
        database_cleanup_interval_seconds = settings.database_cleanup_interval_seconds,
        drain_delay_milliseconds,
        shutdown_timeout_seconds,
        trust_proxy_headers = settings.trust_proxy_headers,
        "starting Robine ID"
    );
    let server_application = application.clone();
    let server = HttpServer::new(move || {
        let worker_application = server_application.clone();
        App::new()
            .app_data(web::Data::new(worker_application.clone()))
            .configure(robine_web::configure)
            .wrap_fn(move |mut request, service| {
                use actix_web::dev::Service;
                let request_id = robine_web::correlation_id_value(
                    request
                        .headers()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok()),
                );
                if let Ok(value) = actix_web::http::header::HeaderValue::from_str(&request_id) {
                    request.headers_mut().insert(
                        actix_web::http::header::HeaderName::from_static("x-request-id"),
                        value,
                    );
                }
                let method = HttpMethodClass::from_method(request.method().as_str());
                let started_at = Instant::now();
                let metrics_application = worker_application.clone();
                let span = tracing::info_span!(
                    "http_request",
                    request_id = %request_id,
                    method = method.label()
                );
                let future = service.call(request);
                async move {
                    let mut response = future.await?;
                    robine_web::secure(response.response_mut());
                    robine_web::set_correlation_id(response.response_mut(), &request_id);
                    metrics_application.metrics().record_http_response(
                        method,
                        response.status().as_u16(),
                        started_at.elapsed(),
                    );
                    tracing::info!(
                        event = "http_request",
                        outcome = "completed",
                        status = response.status().as_u16(),
                        duration_micros = started_at.elapsed().as_micros() as u64,
                        "HTTP request completed"
                    );
                    Ok(response)
                }
                .instrument(span)
            })
    })
    .disable_signals()
    .shutdown_timeout(shutdown_timeout_seconds)
    .bind((settings.host.as_str(), settings.port))?
    .run();
    let server_handle = server.handle();

    tokio::spawn(async move {
        let signal = shutdown_signal().await;
        if application.begin_draining() {
            tracing::info!(
                event = "shutdown",
                outcome = "draining",
                signal,
                drain_delay_milliseconds,
                shutdown_timeout_seconds,
                "shutdown signal received; readiness disabled"
            );
        }
        tokio::time::sleep(Duration::from_millis(drain_delay_milliseconds)).await;
        tracing::info!(
            event = "shutdown",
            outcome = "stopping",
            signal,
            "drain delay elapsed; stopping HTTP server"
        );
        server_handle.stop(true).await;
    });

    server.await
}

fn environment_value(name: &str) -> io::Result<Option<String>> {
    let value = match env::var(name) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            return Err(invalid_setting(name, "must contain valid Unicode"));
        }
    };
    Ok(value)
}

fn parse_port(value: Option<&str>) -> io::Result<u16> {
    let Some(value) = value else {
        return Ok(4001);
    };
    let port = value
        .parse::<u16>()
        .map_err(|_| invalid_setting("PORT", "must be an integer between 1 and 65535"))?;
    if port == 0 {
        return Err(invalid_setting("PORT", "must be between 1 and 65535"));
    }
    Ok(port)
}

fn parse_disableable_interval(
    name: &str,
    value: Option<&str>,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> io::Result<u64> {
    let parsed = parse_bounded_integer(name, value, default, 0, maximum)?;
    if parsed != 0 && parsed < minimum {
        return Err(invalid_setting(
            name,
            &format!("must be 0 or between {minimum} and {maximum}"),
        ));
    }
    Ok(parsed)
}

fn parse_bounded_integer(
    name: &str,
    value: Option<&str>,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> io::Result<u64> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed = value.parse::<u64>().map_err(|_| {
        invalid_setting(
            name,
            &format!("must be an integer between {minimum} and {maximum}"),
        )
    })?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(invalid_setting(
            name,
            &format!("must be between {minimum} and {maximum}"),
        ));
    }
    Ok(parsed)
}

fn parse_boolean(name: &str, value: Option<&str>, default: bool) -> io::Result<bool> {
    let Some(value) = value else {
        return Ok(default);
    };
    if value == "1" || value.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if value == "0" || value.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    Err(invalid_setting(name, "must be true, false, 1, or 0"))
}

fn invalid_setting(name: &str, requirement: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{name} {requirement}"))
}

#[cfg(unix)]
fn spawn_configuration_reload_signal(application: Application) {
    if env::var_os("VERCEL").is_some() || env::var_os("ROBINE_ID_CONFIG_JSON").is_some() {
        return;
    }
    tokio::spawn(async move {
        let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(hangup) => hangup,
            Err(error) => {
                tracing::error!(
                    event = "configuration_reconciliation",
                    outcome = "signal_error",
                    %error,
                    "SIGHUP handler installation failed; periodic reload remains available"
                );
                return;
            }
        };
        while hangup.recv().await.is_some() {
            tracing::info!(
                event = "configuration_reconciliation",
                outcome = "requested",
                trigger = "SIGHUP",
                "immediate configuration reload requested"
            );
            let _ = application.reload_configuration("SIGHUP").await;
        }
        tracing::error!(
            event = "configuration_reconciliation",
            outcome = "signal_error",
            "SIGHUP stream ended; periodic reload remains available"
        );
    });
}

#[cfg(not(unix))]
fn spawn_configuration_reload_signal(_application: Application) {}

#[cfg(unix)]
async fn shutdown_signal() -> &'static str {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::error!(event = "shutdown", outcome = "signal_error", %error, "SIGINT handler failed");
                }
                "SIGINT"
            }
            _ = terminate.recv() => "SIGTERM",
        },
        Err(error) => {
            tracing::error!(
                event = "shutdown",
                outcome = "signal_error",
                %error,
                "SIGTERM handler installation failed; retaining SIGINT shutdown support"
            );
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(event = "shutdown", outcome = "signal_error", %error, "SIGINT handler failed");
            }
            "SIGINT"
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> &'static str {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(event = "shutdown", outcome = "signal_error", %error, "interrupt handler failed");
    }
    "interrupt"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_settings_have_bounded_defaults() {
        assert_eq!(
            ServerEnvironment::default().build().unwrap(),
            ServerSettings {
                host: "127.0.0.1".to_owned(),
                port: 4001,
                reload_interval_milliseconds: 1_000,
                database_cleanup_interval_seconds: 3_600,
                drain_delay_milliseconds: 3_000,
                shutdown_timeout_seconds: 10,
                trust_proxy_headers: false,
            }
        );
    }

    #[test]
    fn disableable_intervals_and_boolean_spellings_are_explicit() {
        let settings = ServerEnvironment {
            reload_interval: Some("0".to_owned()),
            database_cleanup_interval: Some("0".to_owned()),
            trust_proxy_headers: Some("TrUe".to_owned()),
            ..ServerEnvironment::default()
        }
        .build()
        .unwrap();

        assert_eq!(settings.reload_interval_milliseconds, 0);
        assert_eq!(settings.database_cleanup_interval_seconds, 0);
        assert!(settings.trust_proxy_headers);
    }

    #[test]
    fn invalid_server_settings_are_rejected_without_echoing_values() {
        for (environment, expected_name) in [
            (
                ServerEnvironment {
                    port: Some("secret-port-value".to_owned()),
                    ..ServerEnvironment::default()
                },
                "PORT",
            ),
            (
                ServerEnvironment {
                    reload_interval: Some("1".to_owned()),
                    ..ServerEnvironment::default()
                },
                "ROBINE_ID_RELOAD_INTERVAL",
            ),
            (
                ServerEnvironment {
                    database_cleanup_interval: Some("1".to_owned()),
                    ..ServerEnvironment::default()
                },
                "DATABASE_CLEANUP_INTERVAL",
            ),
            (
                ServerEnvironment {
                    trust_proxy_headers: Some("secret-boolean-value".to_owned()),
                    ..ServerEnvironment::default()
                },
                "TRUST_PROXY_HEADERS",
            ),
        ] {
            let error = environment.build().unwrap_err().to_string();
            assert!(error.contains(expected_name));
            assert!(!error.contains("secret-"));
        }
    }

    #[test]
    fn port_zero_and_empty_host_are_rejected() {
        let port_error = ServerEnvironment {
            port: Some("0".to_owned()),
            ..ServerEnvironment::default()
        }
        .build()
        .unwrap_err();
        assert!(port_error.to_string().contains("PORT"));

        let host_error = ServerEnvironment {
            host: Some(String::new()),
            ..ServerEnvironment::default()
        }
        .build()
        .unwrap_err();
        assert!(host_error.to_string().contains("HOST"));
    }
}
