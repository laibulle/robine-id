use actix_web::{App, body::to_bytes, test, web};
use robine_id::{Application, web as robine_web};
use std::sync::OnceLock;
use std::time::Instant;
use tokio::sync::OnceCell;
use tracing::Instrument;
use vercel_runtime::{Error, Request, Response, ResponseBody, run, service_fn};

static APPLICATION: OnceLock<Result<Application, String>> = OnceLock::new();
static MIGRATED: OnceCell<()> = OnceCell::const_new();

struct FunctionRequest {
    method: String,
    uri: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    request_id: String,
    started_at: Instant,
}

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

    let request_id = robine_web::correlation_id_value(
        request
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
    );
    let method = request.method().to_string();
    let started_at = Instant::now();
    let span = tracing::info_span!("http_request", request_id = %request_id, method = %method);
    async move {
        let (parts, body) = request.into_parts();
        let body = http_body_util::BodyExt::collect(body).await?.to_bytes();
        let input = FunctionRequest {
            method,
            uri: parts.uri.to_string(),
            headers: parts
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            body: body.to_vec(),
            request_id,
            started_at,
        };
        dispatch_application(application, input).await
    }
    .instrument(span)
    .await
}

async fn dispatch_application(
    application: Application,
    input: FunctionRequest,
) -> Result<Response<ResponseBody>, Error> {
    let metrics_application = application.clone();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(application))
            .configure(robine_web::configure),
    )
    .await;

    let mut actix_request = test::TestRequest::default()
        .method(actix_web::http::Method::from_bytes(
            input.method.as_bytes(),
        )?)
        .uri(&input.uri);
    for (name, value) in &input.headers {
        if let (Ok(name), Ok(value)) = (
            actix_web::http::header::HeaderName::from_bytes(name.as_bytes()),
            actix_web::http::header::HeaderValue::from_bytes(value),
        ) {
            actix_request = actix_request.insert_header((name, value));
        }
    }
    actix_request = actix_request.insert_header(("x-request-id", input.request_id.clone()));

    let mut response =
        test::call_service(&app, actix_request.set_payload(input.body).to_request()).await;
    robine_web::secure(response.response_mut());
    robine_web::set_correlation_id(response.response_mut(), &input.request_id);
    let status = response.status().as_u16();
    metrics_application
        .metrics()
        .record_http_response(status, input.started_at.elapsed());
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

#[cfg(test)]
mod tests {
    use super::*;
    use robine_id::Snapshot;

    #[actix_web::test]
    async fn forwards_a_vercel_request_through_actix_with_security_headers() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let response = dispatch_application(
            application,
            FunctionRequest {
                method: "GET".to_owned(),
                uri: "/health/live".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_adapter.123".to_owned(),
                started_at: Instant::now(),
            },
        )
        .await
        .expect("Vercel response");

        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("vercel_adapter.123")
        );
        assert!(response.headers().contains_key("content-security-policy"));
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("response body")
            .to_bytes();
        assert_eq!(body, r#"{"status":"live"}"#);
    }
}
