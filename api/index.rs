use actix_web::{App, body::to_bytes, test, web};
use robine_id::{Application, web as robine_web};
use std::sync::OnceLock;
use tokio::sync::OnceCell;
use vercel_runtime::{Error, Request, Response, ResponseBody, run, service_fn};

static APPLICATION: OnceLock<Result<Application, String>> = OnceLock::new();
static MIGRATED: OnceCell<()> = OnceCell::const_new();

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handler)).await
}

async fn handler(request: Request) -> Result<Response<ResponseBody>, Error> {
    tokio::task::spawn_blocking(move || actix_web::rt::System::new().block_on(dispatch(request)))
        .await
        .map_err(|error| -> Error { Box::new(error) })?
}

async fn dispatch(request: Request) -> Result<Response<ResponseBody>, Error> {
    let application = APPLICATION
        .get_or_init(|| Application::load().map_err(|error| error.to_string()))
        .clone()
        .map_err(|error| -> Error { error.into() })?;
    MIGRATED
        .get_or_try_init(|| async {
            application
                .migrate()
                .await
                .map_err(|error| -> Error { Box::new(error) })?;
            Ok::<(), Error>(())
        })
        .await?;

    let (parts, body) = request.into_parts();
    let body = http_body_util::BodyExt::collect(body).await?.to_bytes();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(application))
            .configure(robine_web::configure),
    )
    .await;

    let mut actix_request = test::TestRequest::default()
        .method(actix_web::http::Method::from_bytes(
            parts.method.as_str().as_bytes(),
        )?)
        .uri(&parts.uri.to_string());
    for (name, value) in &parts.headers {
        if let (Ok(name), Ok(value)) = (
            actix_web::http::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            actix_web::http::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            actix_request = actix_request.insert_header((name, value));
        }
    }

    let mut response = test::call_service(&app, actix_request.set_payload(body).to_request()).await;
    robine_web::secure(response.response_mut());
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body())
        .await
        .map_err(|error| error.to_string())?;
    let mut builder = Response::builder().status(status);
    for (name, value) in &headers {
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    Ok(builder.body(ResponseBody::from(body.to_vec()))?)
}
