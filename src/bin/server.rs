use actix_web::{App, HttpServer, middleware::Logger, web};
use robine_id::{Application, web as robine_web};
use std::{env, io};
use tracing_subscriber::EnvFilter;

#[actix_web::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "robine_id=info".into()),
        )
        .init();

    let application = Application::load().map_err(io::Error::other)?;
    application.migrate().await.map_err(io::Error::other)?;
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(4001);

    tracing::info!(%host, %port, "starting Robine ID");
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(web::Data::new(application.clone()))
            .configure(robine_web::configure)
            .wrap_fn(|request, service| {
                use actix_web::dev::Service;
                let future = service.call(request);
                async move {
                    let mut response = future.await?;
                    robine_web::secure(response.response_mut());
                    Ok(response)
                }
            })
    })
    .bind((host, port))?
    .run()
    .await
}
