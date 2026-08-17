use actix_web::{App, HttpServer, middleware::Logger, web};
use robine_id::{Application, web as robine_web};
use std::time::Instant;
use std::{env, io};
use tracing::Instrument;
use tracing_subscriber::EnvFilter;

#[actix_web::main]
async fn main() -> io::Result<()> {
    let application = Application::load().map_err(io::Error::other)?;
    let configured_level = application
        .snapshot()
        .configuration
        .telemetry
        .log_level
        .clone()
        .unwrap_or_else(|| "info".to_owned());
    let configured_level = if configured_level == "warning" {
        "warn"
    } else {
        &configured_level
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("robine_id={configured_level}").into()),
        )
        .init();

    application.migrate().await.map_err(io::Error::other)?;
    application.spawn_configuration_reloader();
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(4001);

    tracing::info!(%host, %port, "starting Robine ID");
    HttpServer::new(move || {
        let worker_application = application.clone();
        App::new()
            .wrap(Logger::default())
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
                let method = request.method().to_string();
                let started_at = Instant::now();
                let metrics_application = worker_application.clone();
                let span = tracing::info_span!(
                    "http_request",
                    request_id = %request_id,
                    method = %method
                );
                let future = service.call(request);
                async move {
                    let mut response = future.await?;
                    robine_web::secure(response.response_mut());
                    robine_web::set_correlation_id(response.response_mut(), &request_id);
                    metrics_application
                        .metrics()
                        .record_http_response(response.status().as_u16(), started_at.elapsed());
                    Ok(response)
                }
                .instrument(span)
            })
    })
    .bind((host, port))?
    .run()
    .await
}
