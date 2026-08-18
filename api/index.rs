use actix_web::{App, HttpResponse, body::MessageBody, body::to_bytes, test, web};
use robine_id::{
    Application, Snapshot, initialize_tracing, metrics::HttpMethodClass, web as robine_web,
};
use std::rc::Rc;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio::sync::{OnceCell, Semaphore, mpsc, oneshot};
use tracing::Instrument;
use vercel_runtime::{Error, Request, Response, ResponseBody, run, service_fn};

static APPLICATION: OnceLock<Result<Application, String>> = OnceLock::new();
static MIGRATED: OnceCell<()> = OnceCell::const_new();
static ACTIX_WORKER: OnceCell<ActixWorker> = OnceCell::const_new();
const MAX_REQUEST_BODY: usize = 16 * 1024;
const WORKER_QUEUE_CAPACITY: usize = 128;
const MAX_CONCURRENT_REQUESTS: usize = 32;

struct FunctionRequest {
    method: String,
    uri: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    request_id: String,
    started_at: Instant,
}

struct FunctionResponse {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

struct WorkerJob {
    input: FunctionRequest,
    response: oneshot::Sender<Result<FunctionResponse, String>>,
}

#[derive(Clone)]
struct ActixWorker {
    sender: mpsc::Sender<WorkerJob>,
    application: Application,
    #[cfg(test)]
    initializations: Arc<AtomicU64>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handler)).await
}

async fn handler(request: Request) -> Result<Response<ResponseBody>, Error> {
    dispatch(request).await
}

async fn dispatch(request: Request) -> Result<Response<ResponseBody>, Error> {
    let application = APPLICATION
        .get_or_init(load_application)
        .clone()
        .map_err(|error| -> Error { error.into() })?;
    initialize_tracing(&application);
    MIGRATED
        .get_or_try_init(|| async {
            application
                .migrate()
                .await
                .map_err(|error| -> Error { Box::new(error) })?;
            application
                .rotate_due_signing_keys()
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
    let method_class = HttpMethodClass::from_method(&method);
    let started_at = Instant::now();
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = method_class.label()
    );
    async move {
        let (parts, body) = request.into_parts();
        let snapshot = application.snapshot();
        let oversized_cors_origin = adapter_rejection_cors_origin(
            &snapshot,
            &method,
            parts.uri.path(),
            parts
                .headers
                .get_all("origin")
                .iter()
                .map(|value| value.to_str().ok()),
        );
        let body = match http_body_util::BodyExt::collect(http_body_util::Limited::new(
            body,
            MAX_REQUEST_BODY,
        ))
        .await
        {
            Ok(body) => body.to_bytes(),
            Err(error) => {
                tracing::warn!(
                    event = "request_rejection",
                    outcome = "rejected",
                    reason = "payload_too_large",
                    "Vercel request body rejected"
                );
                if error
                    .downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    application.metrics().record_http_response(
                        method_class,
                        413,
                        started_at.elapsed(),
                    );
                    return payload_too_large_response(
                        &request_id,
                        oversized_cors_origin.as_deref(),
                        method == "HEAD",
                    );
                }
                return Err(error);
            }
        };
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
        let worker = ACTIX_WORKER
            .get_or_try_init(|| async { ActixWorker::start(application.clone()) })
            .await
            .map_err(|error| -> Error { error.clone().into() })?;
        worker.dispatch(input).await
    }
    .instrument(span)
    .await
}

fn load_application() -> Result<Application, String> {
    if !vercel_configuration_explicit(
        std::env::var_os("VERCEL").is_some(),
        std::env::var_os("ROBINE_ID_CONFIG_JSON").is_some(),
        std::env::var_os("ROBINE_ID_CONFIG").is_some(),
    ) {
        return Err(
            "Vercel deployments require explicit ROBINE_ID_CONFIG_JSON or ROBINE_ID_CONFIG"
                .to_owned(),
        );
    }
    Application::load().map_err(|error| error.to_string())
}

fn vercel_configuration_explicit(vercel: bool, inline: bool, path: bool) -> bool {
    !vercel || inline || path
}

fn adapter_rejection_cors_origin<'a>(
    snapshot: &Snapshot,
    method: &str,
    path: &str,
    mut origins: impl Iterator<Item = Option<&'a str>>,
) -> Option<String> {
    if method != "POST" {
        return None;
    }
    let origin = origins.next()??;
    if origins.next().is_some() {
        return None;
    }
    robine_web::public_client_cors_origin_allowed(snapshot, path, origin).then(|| origin.to_owned())
}

impl ActixWorker {
    fn start(application: Application) -> Result<Self, String> {
        let (sender, mut receiver) = mpsc::channel::<WorkerJob>(WORKER_QUEUE_CAPACITY);
        let worker_application = application.clone();
        #[cfg(test)]
        let initializations = Arc::new(AtomicU64::new(0));
        #[cfg(test)]
        let worker_initializations = initializations.clone();
        std::thread::Builder::new()
            .name("robine-id-vercel-actix".to_owned())
            .spawn(move || {
                actix_web::rt::System::new().block_on(async move {
                    let concurrency = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
                    let service = Rc::new(
                        test::init_service(
                            App::new()
                                .app_data(web::Data::new(application.clone()))
                                .configure(robine_web::configure),
                        )
                        .await,
                    );
                    #[cfg(test)]
                    worker_initializations.fetch_add(1, Ordering::Release);
                    tracing::info!(
                        event = "vercel_actix_worker",
                        outcome = "started",
                        queue_capacity = WORKER_QUEUE_CAPACITY,
                        max_concurrent_requests = MAX_CONCURRENT_REQUESTS,
                        "warm Actix worker started"
                    );

                    while let Some(job) = receiver.recv().await {
                        let Ok(permit) = concurrency.clone().acquire_owned().await else {
                            break;
                        };
                        if job.response.is_closed() {
                            continue;
                        }
                        let service = service.clone();
                        let metrics_application = application.clone();
                        let method_class = HttpMethodClass::from_method(&job.input.method);
                        let span = tracing::info_span!(
                            "http_request",
                            request_id = %job.input.request_id,
                            method = method_class.label()
                        );
                        actix_web::rt::spawn(
                            async move {
                                let _permit = permit;
                                let result = async {
                                    let mut actix_request = test::TestRequest::default()
                                        .method(actix_web::http::Method::from_bytes(
                                            job.input.method.as_bytes(),
                                        )?)
                                        .uri(&job.input.uri);
                                    for (name, value) in &job.input.headers {
                                        if let (Ok(name), Ok(value)) = (
                                            actix_web::http::header::HeaderName::from_bytes(
                                                name.as_bytes(),
                                            ),
                                            actix_web::http::header::HeaderValue::from_bytes(value),
                                        ) {
                                            actix_request =
                                                actix_request.insert_header((name, value));
                                        }
                                    }
                                    actix_request = actix_request.insert_header((
                                        "x-request-id",
                                        job.input.request_id.clone(),
                                    ));

                                    let mut response = test::call_service(
                                        service.as_ref(),
                                        actix_request.set_payload(job.input.body).to_request(),
                                    )
                                    .await;
                                    robine_web::secure(response.response_mut());
                                    robine_web::set_correlation_id(
                                        response.response_mut(),
                                        &job.input.request_id,
                                    );
                                    let status = response.status().as_u16();
                                    metrics_application.metrics().record_http_response(
                                        method_class,
                                        status,
                                        job.input.started_at.elapsed(),
                                    );
                                    tracing::info!(
                                        event = "http_request",
                                        outcome = "completed",
                                        status,
                                        duration_micros =
                                            job.input.started_at.elapsed().as_micros() as u64,
                                        "HTTP request completed"
                                    );
                                    let (_, response) = response.into_parts();
                                    actix_to_function_response(response).await
                                }
                                .await
                                .map_err(|error: Error| error.to_string());
                                let _ = job.response.send(result);
                            }
                            .instrument(span),
                        );
                    }
                });
            })
            .map_err(|error| format!("cannot start the Actix worker: {error}"))?;

        Ok(Self {
            sender,
            application: worker_application,
            #[cfg(test)]
            initializations,
        })
    }

    async fn dispatch(&self, input: FunctionRequest) -> Result<Response<ResponseBody>, Error> {
        let request_id = input.request_id.clone();
        let started_at = input.started_at;
        let method = HttpMethodClass::from_method(&input.method);
        let head = input.method == "HEAD";
        let snapshot = self.application.snapshot();
        let cors_origin = adapter_rejection_cors_origin(
            &snapshot,
            &input.method,
            input.uri.split('?').next().unwrap_or(&input.uri),
            input
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("origin"))
                .map(|(_, value)| std::str::from_utf8(value).ok()),
        );
        let (response, receiver) = oneshot::channel();
        if let Err(error) = self.sender.try_send(WorkerJob { input, response }) {
            let reason = match error {
                mpsc::error::TrySendError::Full(_) => "queue_full",
                mpsc::error::TrySendError::Closed(_) => "worker_unavailable",
            };
            self.application
                .metrics()
                .record_http_response(method, 503, started_at.elapsed());
            tracing::warn!(
                event = "vercel_adapter_rejection",
                outcome = "rejected",
                reason,
                "Vercel request rejected before Actix dispatch"
            );
            return service_unavailable_response(&request_id, cors_origin.as_deref(), head);
        }
        match receiver.await {
            Ok(Ok(response)) => function_response_to_vercel(response),
            Ok(Err(error)) => {
                self.application
                    .metrics()
                    .record_http_response(method, 503, started_at.elapsed());
                tracing::error!(
                    event = "vercel_adapter_failure",
                    outcome = "failed",
                    diagnostic = %error,
                    "Actix worker could not produce a response"
                );
                service_unavailable_response(&request_id, cors_origin.as_deref(), head)
            }
            Err(_) => {
                self.application
                    .metrics()
                    .record_http_response(method, 503, started_at.elapsed());
                tracing::error!(
                    event = "vercel_adapter_failure",
                    outcome = "failed",
                    reason = "worker_stopped",
                    "Actix worker stopped before completing a request"
                );
                service_unavailable_response(&request_id, cors_origin.as_deref(), head)
            }
        }
    }

    #[cfg(test)]
    fn initialization_count(&self) -> u64 {
        self.initializations.load(Ordering::Acquire)
    }
}

async fn actix_to_function_response<B>(response: HttpResponse<B>) -> Result<FunctionResponse, Error>
where
    B: MessageBody,
    B::Error: std::fmt::Display,
{
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body())
        .await
        .map_err(|error| error.to_string())?;
    Ok(FunctionResponse {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect(),
        body: body.to_vec(),
    })
}

fn function_response_to_vercel(
    response: FunctionResponse,
) -> Result<Response<ResponseBody>, Error> {
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    Ok(builder.body(ResponseBody::from(response.body))?)
}

fn payload_too_large_response(
    request_id: &str,
    cors_origin: Option<&str>,
    head: bool,
) -> Result<Response<ResponseBody>, Error> {
    let body = serde_json::json!({"error": "payload_too_large"}).to_string();
    let mut builder = Response::builder()
        .status(413)
        .header("content-type", "application/json")
        .header("content-length", body.len())
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .header("x-request-id", request_id)
        .header(
            "cross-origin-resource-policy",
            if cors_origin.is_some() {
                "cross-origin"
            } else {
                "same-origin"
            },
        );
    if let Some(origin) = cors_origin {
        builder = builder
            .header("access-control-allow-origin", origin)
            .header("vary", "Origin");
    }
    for &(name, value) in robine_web::SECURITY_HEADERS {
        builder = builder.header(name, value);
    }
    Ok(builder.body(ResponseBody::from(if head { String::new() } else { body }))?)
}

fn service_unavailable_response(
    request_id: &str,
    cors_origin: Option<&str>,
    head: bool,
) -> Result<Response<ResponseBody>, Error> {
    let body = serde_json::json!({"error": "temporarily_unavailable"}).to_string();
    let mut builder = Response::builder()
        .status(503)
        .header("content-type", "application/json")
        .header("content-length", body.len())
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .header("retry-after", "1")
        .header("x-request-id", request_id)
        .header(
            "cross-origin-resource-policy",
            if cors_origin.is_some() {
                "cross-origin"
            } else {
                "same-origin"
            },
        );
    if let Some(origin) = cors_origin {
        builder = builder
            .header("access-control-allow-origin", origin)
            .header("access-control-expose-headers", "Retry-After")
            .header("vary", "Origin");
    }
    for &(name, value) in robine_web::SECURITY_HEADERS {
        builder = builder.header(name, value);
    }
    Ok(builder.body(ResponseBody::from(if head { String::new() } else { body }))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
    use rand_core::OsRng;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};

    #[actix_web::test]
    async fn preserves_non_cacheable_default_errors_through_vercel() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let worker = ActixWorker::start(application).expect("Actix worker");

        for (uri, request_id) in [
            ("/not-routed", "vercel_not_found.123"),
            ("/missing/jwks.json", "vercel_unknown_issuer.123"),
        ] {
            let response = worker
                .dispatch(FunctionRequest {
                    method: "GET".to_owned(),
                    uri: uri.to_owned(),
                    headers: vec![],
                    body: vec![],
                    request_id: request_id.to_owned(),
                    started_at: Instant::now(),
                })
                .await
                .expect("Vercel error response");

            assert_eq!(response.status(), 404);
            assert_eq!(
                response
                    .headers()
                    .get("cache-control")
                    .and_then(|value| value.to_str().ok()),
                Some("no-store")
            );
            assert_eq!(
                response
                    .headers()
                    .get("pragma")
                    .and_then(|value| value.to_str().ok()),
                Some("no-cache")
            );
        }
    }

    #[actix_web::test]
    async fn forwards_accept_language_to_browser_errors() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let worker = ActixWorker::start(application).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/default/authorize".to_owned(),
                headers: vec![(
                    "accept-language".to_owned(),
                    b"en;q=0.2, fr-FR;q=0.9".to_vec(),
                )],
                body: vec![],
                request_id: "vercel_accept_language.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel localized browser error");

        assert_eq!(response.status(), 400);
        assert_eq!(
            response
                .headers()
                .get("content-language")
                .and_then(|value| value.to_str().ok()),
            Some("fr")
        );
        assert_eq!(
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("vercel_accept_language.123")
        );
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("localized browser error body")
            .to_bytes();
        let body = std::str::from_utf8(&body).expect("UTF-8 localized browser error");
        assert!(body.contains("<html lang=\"fr\">"));
        assert!(body.contains("Demande d’autorisation refusée"));
    }

    #[actix_web::test]
    async fn preserves_protocol_method_negotiation_through_vercel() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let worker = ActixWorker::start(application).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/default/token".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_method_not_allowed.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel method negotiation response");

        assert_eq!(response.status(), 405);
        assert_eq!(
            response
                .headers()
                .get("allow")
                .and_then(|value| value.to_str().ok()),
            Some("POST, OPTIONS")
        );
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get("pragma")
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        assert_eq!(
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("vercel_method_not_allowed.123")
        );

        let head = worker
            .dispatch(FunctionRequest {
                method: "HEAD".to_owned(),
                uri: "/default/token".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_method_not_allowed.head".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel HEAD method negotiation response");
        assert_eq!(head.status(), 405);
        assert_eq!(
            head.headers()
                .get("allow")
                .and_then(|value| value.to_str().ok()),
            Some("POST, OPTIONS")
        );
        assert!(
            head.headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.parse::<usize>().is_ok_and(|length| length > 0))
        );
        assert!(
            http_body_util::BodyExt::collect(head.into_body())
                .await
                .expect("HEAD method negotiation body")
                .to_bytes()
                .is_empty()
        );

        let public_metadata = worker
            .dispatch(FunctionRequest {
                method: "PUT".to_owned(),
                uri: "/default/.well-known/openid-configuration".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_public_metadata_method_not_allowed.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel public metadata method negotiation response");
        assert_eq!(public_metadata.status(), 405);
        assert_eq!(
            public_metadata
                .headers()
                .get("allow")
                .and_then(|value| value.to_str().ok()),
            Some("GET, HEAD, OPTIONS")
        );
        assert_eq!(
            public_metadata
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );

        let rejected_public_preflight = worker
            .dispatch(FunctionRequest {
                method: "OPTIONS".to_owned(),
                uri: "/default/.well-known/openid-configuration".to_owned(),
                headers: vec![
                    ("origin".to_owned(), b"https://browser.example".to_vec()),
                    ("access-control-request-method".to_owned(), b"POST".to_vec()),
                    (
                        "access-control-request-headers".to_owned(),
                        b"Authorization".to_vec(),
                    ),
                ],
                body: vec![],
                request_id: "vercel_public_metadata_preflight_rejected.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel rejected public metadata preflight");
        assert_eq!(rejected_public_preflight.status(), 403);
        assert_eq!(
            rejected_public_preflight
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert!(
            !rejected_public_preflight
                .headers()
                .contains_key("access-control-allow-origin")
        );
        assert!(
            http_body_util::BodyExt::collect(rejected_public_preflight.into_body())
                .await
                .expect("rejected public metadata preflight body")
                .to_bytes()
                .is_empty()
        );

        let webfinger = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/.well-known/webfinger?rel=missing-resource".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_webfinger_rejection.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel malformed WebFinger response");
        assert_eq!(webfinger.status(), 400);
        assert_eq!(
            webfinger
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/jrd+json")
        );
        assert_eq!(
            webfinger
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        assert_eq!(
            webfinger
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );

        let session_origin = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/default/check-session/origin?client_id=missing-origin".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_session_origin_rejection.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel malformed session-origin response");
        assert_eq!(session_origin.status(), 400);
        assert_eq!(
            session_origin
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert!(
            http_body_util::BodyExt::collect(session_origin.into_body())
                .await
                .expect("session-origin rejection body")
                .to_bytes()
                .is_empty()
        );
    }

    #[actix_web::test]
    async fn reuses_a_warm_actix_worker_with_security_headers() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let worker = ActixWorker::start(application).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/health/live".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_adapter.123".to_owned(),
                started_at: Instant::now(),
            })
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
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get("pragma")
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        assert!(response.headers().contains_key("content-security-policy"));
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("response body")
            .to_bytes();
        assert_eq!(body, r#"{"status":"live"}"#);

        let head = worker
            .dispatch(FunctionRequest {
                method: "HEAD".to_owned(),
                uri: "/health/live".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_adapter.head".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel HEAD health response");
        assert_eq!(head.status(), 200);
        assert_eq!(
            head.headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some(r#"{"status":"live"}"#.len().to_string().as_str())
        );
        assert_eq!(
            head.headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert!(
            http_body_util::BodyExt::collect(head.into_body())
                .await
                .expect("HEAD health body")
                .to_bytes()
                .is_empty()
        );

        let userinfo = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/default/userinfo".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_userinfo_metric.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel UserInfo rejection");
        assert_eq!(userinfo.status(), 401);
        let metrics = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/metrics".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_metrics.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel metrics response");
        assert_eq!(metrics.status(), 200);
        let metrics = http_body_util::BodyExt::collect(metrics.into_body())
            .await
            .expect("Vercel metrics body")
            .to_bytes();
        assert!(
            metrics
                .windows(b"robine_id_userinfo_total{outcome=\"failure\"} 1".len())
                .any(|window| { window == b"robine_id_userinfo_total{outcome=\"failure\"} 1" })
        );
        assert!(
            metrics
                .windows(b"robine_id_http_method_requests_total{method=\"GET\"} 2".len())
                .any(|window| {
                    window == b"robine_id_http_method_requests_total{method=\"GET\"} 2"
                })
        );
        assert!(
            metrics
                .windows(b"robine_id_http_method_requests_total{method=\"HEAD\"} 1".len())
                .any(|window| {
                    window == b"robine_id_http_method_requests_total{method=\"HEAD\"} 1"
                })
        );

        let second = worker.dispatch(FunctionRequest {
            method: "GET".to_owned(),
            uri: "/health/live".to_owned(),
            headers: vec![],
            body: vec![],
            request_id: "vercel_adapter.456".to_owned(),
            started_at: Instant::now(),
        });
        let third = worker.dispatch(FunctionRequest {
            method: "GET".to_owned(),
            uri: "/health/live".to_owned(),
            headers: vec![],
            body: vec![],
            request_id: "vercel_adapter.789".to_owned(),
            started_at: Instant::now(),
        });
        let (second_response, third_response) = tokio::join!(second, third);
        let second_response = second_response.expect("second Vercel response");
        let third_response = third_response.expect("concurrent Vercel response");
        assert_eq!(second_response.status(), 200);
        assert_eq!(third_response.status(), 200);
        assert_eq!(worker.initialization_count(), 1);
    }

    #[actix_web::test]
    async fn preserves_metrics_bearer_authentication_through_vercel() {
        let token = "vercel_metrics_token_abcdefghijklmnopqrstuvwxyz012345";
        let application = Application::without_database_with_metrics_bearer_token(
            Snapshot::load().expect("development configuration should load"),
            zeroize::Zeroizing::new(token.to_owned()),
        )
        .expect("valid metrics token");
        let worker = ActixWorker::start(application).expect("Actix worker");

        let unauthorized = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/metrics".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_metrics_unauthorized.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel metrics rejection");
        assert_eq!(unauthorized.status(), 401);
        assert_eq!(
            unauthorized
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"metrics\"")
        );

        let authorized = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/metrics".to_owned(),
                headers: vec![(
                    "authorization".to_owned(),
                    format!("Bearer {token}").into_bytes(),
                )],
                body: vec![],
                request_id: "vercel_metrics_authorized.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel metrics response");
        assert_eq!(authorized.status(), 200);
        let body = http_body_util::BodyExt::collect(authorized.into_body())
            .await
            .expect("Vercel metrics body")
            .to_bytes();
        assert!(
            body.windows(b"robine_id_http_requests_total".len())
                .any(|window| window == b"robine_id_http_requests_total")
        );
    }

    #[actix_web::test]
    async fn forwards_conditionally_cacheable_embedded_assets() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let worker = ActixWorker::start(application).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/robots.txt".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_asset.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel asset response");

        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        assert!(response.headers().contains_key("content-security-policy"));
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .expect("asset ETag")
            .to_owned();
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("asset body")
            .to_bytes();
        assert_eq!(body.as_ref(), b"User-agent: *\nDisallow: /\n");

        let compressed = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/robots.txt".to_owned(),
                headers: vec![("accept-encoding".to_owned(), b"gzip".to_vec())],
                body: vec![],
                request_id: "vercel_asset.gzip".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("compressed Vercel asset response");
        assert_eq!(compressed.status(), 200);
        assert_eq!(
            compressed
                .headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("gzip")
        );
        assert!(
            compressed
                .headers()
                .get("etag")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("W/\""))
        );
        let compressed_body = http_body_util::BodyExt::collect(compressed.into_body())
            .await
            .expect("compressed asset body")
            .to_bytes();
        assert!(compressed_body.starts_with(&[0x1f, 0x8b]));

        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/robots.txt".to_owned(),
                headers: vec![("if-none-match".to_owned(), etag.as_bytes().to_vec())],
                body: vec![],
                request_id: "vercel_asset.456".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("conditional Vercel asset response");
        assert_eq!(response.status(), 304);
        assert_eq!(
            response
                .headers()
                .get("etag")
                .and_then(|value| value.to_str().ok()),
            Some(etag.as_str())
        );
        assert!(response.headers().contains_key("content-security-policy"));
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("conditional asset body")
            .to_bytes();
        assert!(body.is_empty());

        let response = worker
            .dispatch(FunctionRequest {
                method: "HEAD".to_owned(),
                uri: "/robots.txt".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_asset.789".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel asset HEAD response");
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some("26")
        );
        assert!(response.headers().contains_key("etag"));
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("asset HEAD body")
            .to_bytes();
        assert!(body.is_empty());
    }

    #[actix_web::test]
    async fn renders_versioned_remote_branding_without_a_runtime_asset_directory() {
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        snapshot.configuration.branding.logo =
            Some("https://cdn.example/logo.svg?theme=dark".to_owned());
        snapshot.configuration.branding.favicon = Some("/favicon.ico".to_owned());
        snapshot.revision = "asset-revision-123456".to_owned();
        let worker =
            ActixWorker::start(Application::without_database(snapshot)).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_branding.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("branded Vercel response");

        assert_eq!(response.status(), 200);
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("branded response body")
            .to_bytes();
        let body = std::str::from_utf8(&body).expect("UTF-8 branded page");
        assert!(
            body.contains("src=\"https://cdn.example/logo.svg?theme=dark&#38;rev=asset-revisi\"")
        );
        assert!(body.contains("rel=\"icon\" href=\"/favicon.ico?rev=asset-revisi\""));
    }

    #[actix_web::test]
    async fn converts_bounded_adapter_rejections_to_secure_responses() {
        let response = payload_too_large_response("vercel_limit.123", None, false)
            .expect("Vercel rejection response");
        assert_eq!(response.status(), 413);
        assert_eq!(
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("vercel_limit.123")
        );
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get("pragma")
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(
            response
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.parse::<usize>().is_ok_and(|length| length > 0))
        );
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("adapter rejection body")
            .to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("adapter rejection JSON"),
            serde_json::json!({"error": "payload_too_large"})
        );

        let response = payload_too_large_response(
            "vercel_cors_limit.123",
            Some("http://localhost:4002"),
            false,
        )
        .expect("CORS-aware Vercel rejection response");
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );
        assert_eq!(
            response
                .headers()
                .get("vary")
                .and_then(|value| value.to_str().ok()),
            Some("Origin")
        );
        assert_eq!(
            response
                .headers()
                .get("cross-origin-resource-policy")
                .and_then(|value| value.to_str().ok()),
            Some("cross-origin")
        );

        let head = payload_too_large_response("vercel_limit.head", None, true)
            .expect("Vercel HEAD rejection response");
        assert_eq!(head.status(), 413);
        assert!(
            head.headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.parse::<usize>().is_ok_and(|length| length > 0))
        );
        assert!(
            http_body_util::BodyExt::collect(head.into_body())
                .await
                .expect("HEAD adapter rejection body")
                .to_bytes()
                .is_empty()
        );
    }

    #[actix_web::test]
    async fn restricts_adapter_rejection_cors_to_one_registered_public_origin() {
        let snapshot = Snapshot::load().expect("development configuration should load");
        let allowed = "http://localhost:4002";

        assert_eq!(
            adapter_rejection_cors_origin(
                &snapshot,
                "POST",
                "/default/token",
                [Some(allowed)].into_iter(),
            )
            .as_deref(),
            Some(allowed)
        );
        for (method, path, origins) in [
            ("GET", "/default/token", vec![Some(allowed)]),
            ("POST", "/default/authorize", vec![Some(allowed)]),
            (
                "POST",
                "/default/token",
                vec![Some("https://unregistered.example")],
            ),
            ("POST", "/default/token", vec![Some(allowed), Some(allowed)]),
            ("POST", "/default/token", vec![None]),
        ] {
            assert_eq!(
                adapter_rejection_cors_origin(&snapshot, method, path, origins.into_iter(),),
                None,
                "{method} {path}"
            );
        }
    }

    #[actix_web::test]
    async fn rejects_a_full_worker_queue_with_a_secure_retryable_response() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let (sender, _receiver) = mpsc::channel(1);
        let (held_response, _held_receiver) = oneshot::channel();
        assert!(
            sender
                .try_send(WorkerJob {
                    input: FunctionRequest {
                        method: "GET".to_owned(),
                        uri: "/health/live".to_owned(),
                        headers: vec![],
                        body: vec![],
                        request_id: "vercel_held.123".to_owned(),
                        started_at: Instant::now(),
                    },
                    response: held_response,
                })
                .is_ok()
        );
        let worker = ActixWorker {
            sender,
            application,
            initializations: Arc::new(AtomicU64::new(0)),
        };

        let response = worker
            .dispatch(FunctionRequest {
                method: "HEAD".to_owned(),
                uri: "/health/live".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_overload.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("bounded overload response");

        assert_eq!(response.status(), 503);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        assert_eq!(
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("vercel_overload.123")
        );
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get("pragma")
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(
            response
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.parse::<usize>().is_ok_and(|length| length > 0))
        );
        assert!(
            http_body_util::BodyExt::collect(response.into_body())
                .await
                .expect("HEAD overload body")
                .to_bytes()
                .is_empty()
        );
        assert!(
            worker
                .application
                .metrics()
                .render("overload-test", false)
                .contains("robine_id_http_method_requests_total{method=\"HEAD\"} 1")
        );

        let response = worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/token".to_owned(),
                headers: vec![("origin".to_owned(), b"http://localhost:4002".to_vec())],
                body: vec![],
                request_id: "vercel_browser_overload.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("CORS-aware overload response");
        assert_eq!(response.status(), 503);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-expose-headers")
                .and_then(|value| value.to_str().ok()),
            Some("Retry-After")
        );
        assert_eq!(
            response
                .headers()
                .get("cross-origin-resource-policy")
                .and_then(|value| value.to_str().ok()),
            Some("cross-origin")
        );
    }

    #[actix_web::test]
    async fn forwards_post_serialized_logout_initiation_through_vercel() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let worker = ActixWorker::start(application).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/logout".to_owned(),
                headers: vec![(
                    "content-type".to_owned(),
                    b"application/x-www-form-urlencoded".to_vec(),
                )],
                body: b"client_id=rust-development-client&ui_locales=fr".to_vec(),
                request_id: "vercel_logout.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel logout response");

        assert_eq!(response.status(), 503);
        assert_eq!(
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("vercel_logout.123")
        );
        assert!(response.headers().contains_key("content-security-policy"));
    }

    #[actix_web::test]
    async fn forwards_public_client_token_and_revocation_preflights_through_vercel() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let worker = ActixWorker::start(application).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "OPTIONS".to_owned(),
                uri: "/default/token".to_owned(),
                headers: vec![
                    ("origin".to_owned(), b"http://localhost:4002".to_vec()),
                    ("access-control-request-method".to_owned(), b"POST".to_vec()),
                    (
                        "access-control-request-headers".to_owned(),
                        b"Content-Type, DPoP".to_vec(),
                    ),
                ],
                body: vec![],
                request_id: "vercel_cors.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel preflight response");

        assert_eq!(response.status(), 204);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-methods")
                .and_then(|value| value.to_str().ok()),
            Some("POST")
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-headers")
                .and_then(|value| value.to_str().ok()),
            Some("Content-Type, DPoP")
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-expose-headers")
                .and_then(|value| value.to_str().ok()),
            Some("DPoP-Nonce")
        );

        let response = worker
            .dispatch(FunctionRequest {
                method: "OPTIONS".to_owned(),
                uri: "/default/revoke".to_owned(),
                headers: vec![
                    ("origin".to_owned(), b"http://localhost:4002".to_vec()),
                    ("access-control-request-method".to_owned(), b"POST".to_vec()),
                    (
                        "access-control-request-headers".to_owned(),
                        b"Content-Type".to_vec(),
                    ),
                ],
                body: vec![],
                request_id: "vercel_revocation_cors.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel revocation preflight response");

        assert_eq!(response.status(), 204);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-headers")
                .and_then(|value| value.to_str().ok()),
            Some("Content-Type")
        );

        let response = worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/revoke".to_owned(),
                headers: vec![
                    ("origin".to_owned(), b"http://localhost:4002".to_vec()),
                    (
                        "content-type".to_owned(),
                        b"application/x-www-form-urlencoded".to_vec(),
                    ),
                ],
                body: b"client_id=rust-development-client".to_vec(),
                request_id: "vercel_malformed_revocation.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel malformed revocation response");
        assert_eq!(response.status(), 400);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );
        assert_eq!(
            response
                .headers()
                .get("pragma")
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
    }

    #[actix_web::test]
    async fn forwards_jarm_discovery_through_vercel() {
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        snapshot.configuration.authorization_detail_types.push(
            robine_id::configuration::AuthorizationDetailType {
                type_id: "account_information".to_owned(),
                name: "Account information".to_owned(),
                allowed_fields: vec!["actions".to_owned()],
                required_fields: vec!["actions".to_owned()],
            },
        );
        snapshot.configuration.clients[0].authorization_details_types =
            vec!["account_information".to_owned()];
        let userinfo_resource = format!(
            "{}/userinfo",
            snapshot.configuration.issuers[0].url.trim_end_matches('/')
        );
        let application = Application::without_database(snapshot);
        let worker = ActixWorker::start(application).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/.well-known/openid-configuration/default".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_jarm_discovery.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel discovery response");

        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        assert_eq!(
            response
                .headers()
                .get("cross-origin-resource-policy")
                .and_then(|value| value.to_str().ok()),
            Some("cross-origin")
        );
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("discovery body")
            .to_bytes();
        let body: serde_json::Value =
            serde_json::from_slice(&body).expect("discovery JSON through Vercel");
        assert_eq!(
            body["authorization_signing_alg_values_supported"],
            serde_json::json!(["RS256"])
        );
        assert_eq!(
            body["userinfo_signing_alg_values_supported"],
            serde_json::json!(["RS256"])
        );
        assert_eq!(
            body["introspection_signing_alg_values_supported"],
            serde_json::json!(["RS256"])
        );
        assert_eq!(
            body["dpop_signing_alg_values_supported"],
            serde_json::json!(["EdDSA", "ES256", "RS256"])
        );
        assert_eq!(body["request_uri_parameter_supported"], false);
        assert!(
            body["pushed_authorization_request_endpoint"]
                .as_str()
                .is_some_and(|endpoint| endpoint.ends_with("/par"))
        );
        assert_eq!(
            body["token_endpoint_auth_signing_alg_values_supported"],
            serde_json::json!(["EdDSA", "ES256", "HS256", "RS256"])
        );
        assert_eq!(
            body["response_modes_supported"],
            serde_json::json!(["query", "form_post", "jwt", "query.jwt", "form_post.jwt"])
        );
        assert_eq!(
            body["authorization_details_types_supported"],
            serde_json::json!(["account_information"])
        );
        assert_eq!(
            body["ui_locales_supported"],
            serde_json::json!(["en", "fr"])
        );
        assert_eq!(
            body["protected_resources"],
            serde_json::json!([userinfo_resource.clone()])
        );
        let discovered_issuer = body["issuer"].as_str().expect("issuer URL");
        if discovered_issuer.starts_with("https://") {
            assert_eq!(
                body["check_session_iframe"],
                format!("{discovered_issuer}/check-session")
            );
        } else {
            assert!(body["check_session_iframe"].is_null());
        }

        let oauth_metadata = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/.well-known/oauth-authorization-server/default".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_oauth_metadata.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel OAuth authorization server metadata response");
        assert_eq!(oauth_metadata.status(), 200);
        assert!(oauth_metadata.headers().contains_key("etag"));
        let oauth_metadata = http_body_util::BodyExt::collect(oauth_metadata.into_body())
            .await
            .expect("OAuth metadata body")
            .to_bytes();
        let oauth_metadata: serde_json::Value =
            serde_json::from_slice(&oauth_metadata).expect("OAuth metadata JSON through Vercel");
        assert_eq!(oauth_metadata["issuer"], body["issuer"]);
        assert_eq!(
            oauth_metadata["token_endpoint"],
            format!("{}/token", body["issuer"].as_str().expect("issuer URL"))
        );
        assert_eq!(
            oauth_metadata["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );

        let discovered_issuer = body["issuer"].as_str().expect("discovered issuer URL");
        let webfinger_resource = format!("{discovered_issuer}/browser");
        let webfinger_query = serde_urlencoded::to_string([
            ("resource", webfinger_resource.as_str()),
            ("rel", "http://openid.net/specs/connect/1.0/issuer"),
        ])
        .expect("WebFinger query");
        let webfinger_uri = format!("/.well-known/webfinger?{webfinger_query}");
        let webfinger = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: webfinger_uri.clone(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_webfinger.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel WebFinger response");
        assert_eq!(webfinger.status(), 200);
        assert_eq!(
            webfinger
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/jrd+json")
        );
        assert_eq!(
            webfinger
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        let webfinger_etag = webfinger
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .expect("WebFinger ETag")
            .to_owned();
        let webfinger_body = http_body_util::BodyExt::collect(webfinger.into_body())
            .await
            .expect("WebFinger body")
            .to_bytes();
        let webfinger_body: serde_json::Value =
            serde_json::from_slice(&webfinger_body).expect("WebFinger JSON through Vercel");
        assert_eq!(webfinger_body["subject"], webfinger_resource);
        assert_eq!(webfinger_body["links"][0]["href"], discovered_issuer);

        let webfinger_revalidation = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: webfinger_uri,
                headers: vec![("if-none-match".to_owned(), webfinger_etag.into_bytes())],
                body: vec![],
                request_id: "vercel_webfinger_revalidation.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel conditional WebFinger response");
        assert_eq!(webfinger_revalidation.status(), 304);
        assert_eq!(
            webfinger_revalidation
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        assert!(
            http_body_util::BodyExt::collect(webfinger_revalidation.into_body())
                .await
                .expect("conditional WebFinger body")
                .to_bytes()
                .is_empty()
        );

        let preflight = worker
            .dispatch(FunctionRequest {
                method: "OPTIONS".to_owned(),
                uri: "/default/jwks.json".to_owned(),
                headers: vec![
                    ("origin".to_owned(), b"https://browser.example".to_vec()),
                    ("access-control-request-method".to_owned(), b"GET".to_vec()),
                    (
                        "access-control-request-headers".to_owned(),
                        b"If-None-Match".to_vec(),
                    ),
                ],
                body: vec![],
                request_id: "vercel_public_metadata_cors.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("public metadata CORS preflight");
        assert_eq!(preflight.status(), 204);
        assert_eq!(
            preflight
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        assert_eq!(
            preflight
                .headers()
                .get("access-control-allow-methods")
                .and_then(|value| value.to_str().ok()),
            Some("GET, HEAD, OPTIONS")
        );
        assert_eq!(
            preflight
                .headers()
                .get("access-control-allow-headers")
                .and_then(|value| value.to_str().ok()),
            Some("If-None-Match")
        );

        let iframe = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/default/check-session".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_check_session.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel check-session iframe");
        if discovered_issuer.starts_with("https://") {
            assert_eq!(iframe.status(), 200);
            assert!(!iframe.headers().contains_key("x-frame-options"));
            assert_eq!(
                iframe
                    .headers()
                    .get("cross-origin-resource-policy")
                    .and_then(|value| value.to_str().ok()),
                Some("cross-origin")
            );
            let iframe_body = http_body_util::BodyExt::collect(iframe.into_body())
                .await
                .expect("check-session iframe body")
                .to_bytes();
            assert!(
                std::str::from_utf8(&iframe_body)
                    .expect("UTF-8 iframe")
                    .contains("/assets/check-session.js")
            );
        } else {
            assert_eq!(iframe.status(), 404);
        }

        let origin = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/default/check-session/origin?client_id=rust-development-client&origin=http%3A%2F%2Flocalhost%3A4002".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_check_session_origin.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel session origin validation");
        assert_eq!(
            origin.status(),
            if discovered_issuer.starts_with("https://") {
                204
            } else {
                400
            }
        );

        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/.well-known/oauth-protected-resource/default/userinfo".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_resource_metadata.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel protected resource metadata response");
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        let metadata = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("protected resource metadata body")
            .to_bytes();
        let metadata: serde_json::Value =
            serde_json::from_slice(&metadata).expect("resource metadata JSON through Vercel");
        assert_eq!(metadata["resource"], userinfo_resource);
        assert_eq!(
            metadata["dpop_signing_alg_values_supported"],
            serde_json::json!(["EdDSA", "ES256", "RS256"])
        );
    }

    #[actix_web::test]
    async fn forwards_pushed_authorization_requests_through_vercel() {
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        snapshot.configuration.authorization_detail_types.push(
            robine_id::configuration::AuthorizationDetailType {
                type_id: "account_information".to_owned(),
                name: "Account information".to_owned(),
                allowed_fields: vec!["actions".to_owned()],
                required_fields: vec!["actions".to_owned()],
            },
        );
        snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "rust-development-client")
            .expect("development client")
            .authorization_details_types = vec!["account_information".to_owned()];
        let application = Application::without_database(snapshot);
        let worker = ActixWorker::start(application).expect("Actix worker");
        let body = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", "rust-development-client"),
            ("redirect_uri", "http://localhost:4002/callback"),
            ("scope", "openid profile email"),
            ("state", "vercel-par-state"),
            ("nonce", "vercel-par-nonce"),
            (
                "code_challenge",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("code_challenge_method", "S256"),
            (
                "authorization_details",
                r#"[{"type":"account_information","actions":["read_balances"]}]"#,
            ),
        ])
        .expect("PAR form");
        let response = worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/par".to_owned(),
                headers: vec![(
                    "content-type".to_owned(),
                    b"application/x-www-form-urlencoded".to_vec(),
                )],
                body: body.into_bytes(),
                request_id: "vercel_par.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel PAR response");

        assert_eq!(response.status(), 503);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert!(response.headers().contains_key("content-security-policy"));
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("PAR response body")
            .to_bytes();
        assert!(
            body.windows(23)
                .any(|value| value == b"temporarily_unavailable")
        );
    }

    #[actix_web::test]
    async fn forwards_client_credentials_requests_through_vercel() {
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        snapshot.configuration.issuers[0]
            .scopes
            .push("service.read".to_owned());
        let mut other = snapshot.configuration.issuers[0].clone();
        other.id = "other".to_owned();
        other.url = "https://id.example/other".to_owned();
        snapshot.configuration.issuers.push(other);
        snapshot
            .configuration
            .clients
            .push(robine_id::configuration::Client {
                enabled: true,
                issuer_ids: vec!["default".to_owned()],
                id: "vercel-service".to_owned(),
                name: "Vercel service".to_owned(),
                client_type: "confidential".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier: None,
                redirect_uris: vec![],
                post_logout_redirect_uris: vec![],
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                resources: vec!["https://api.example/resource".to_owned()],
                scopes: vec!["service.read".to_owned()],
                grant_types: vec!["client_credentials".to_owned()],
                pkce_required: None,
                nonce_required: None,
                consent_required: None,
                introspection_allowed: false,
                userinfo_signed_response_alg: None,
                require_pushed_authorization_requests: false,
                require_signed_request_object: false,
                request_object_jwks: None,
                required_acr: None,
                max_authentication_age: None,
                actor_token_exchange_allowed: false,
                authorized_actor_clients: vec![],
                authorization_details_types: vec![],
                authentication_method: Some("client_secret_basic".to_owned()),
                secret_reference: Some(serde_json::json!({
                    "provider": "env",
                    "key": "PATH"
                })),
                jwks: None,
                branding: None,
            });
        let basic = base64::engine::general_purpose::STANDARD.encode(format!(
            "vercel-service:{}",
            std::env::var("PATH").expect("test PATH")
        ));
        let body = serde_urlencoded::to_string([
            ("grant_type", "client_credentials"),
            ("scope", "service.read"),
        ])
        .expect("client credentials form");
        let mut disabled_snapshot = snapshot.clone();
        disabled_snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "vercel-service")
            .expect("configured service")
            .enabled = false;
        let disabled_worker = ActixWorker::start(Application::without_database(disabled_snapshot))
            .expect("disabled Actix worker");
        let response = disabled_worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/token".to_owned(),
                headers: vec![
                    (
                        "content-type".to_owned(),
                        b"application/x-www-form-urlencoded".to_vec(),
                    ),
                    (
                        "authorization".to_owned(),
                        format!("Basic {basic}").into_bytes(),
                    ),
                ],
                body: body.clone().into_bytes(),
                request_id: "vercel_disabled_service.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("disabled Vercel client response");
        assert_eq!(response.status(), 401);
        let response_body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("disabled client response body")
            .to_bytes();
        assert!(
            response_body
                .windows(b"invalid_client".len())
                .any(|window| window == b"invalid_client")
        );

        let cross_issuer_worker =
            ActixWorker::start(Application::without_database(snapshot.clone()))
                .expect("cross-issuer Actix worker");
        let response = cross_issuer_worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/other/token".to_owned(),
                headers: vec![
                    (
                        "content-type".to_owned(),
                        b"application/x-www-form-urlencoded".to_vec(),
                    ),
                    (
                        "authorization".to_owned(),
                        format!("Basic {basic}").into_bytes(),
                    ),
                ],
                body: body.clone().into_bytes(),
                request_id: "vercel_cross_issuer_service.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("cross-issuer Vercel client response");
        assert_eq!(response.status(), 401);
        let response_body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("cross-issuer client response body")
            .to_bytes();
        assert!(
            response_body
                .windows(b"invalid_client".len())
                .any(|window| window == b"invalid_client")
        );

        let worker =
            ActixWorker::start(Application::without_database(snapshot)).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/token".to_owned(),
                headers: vec![
                    (
                        "content-type".to_owned(),
                        b"application/x-www-form-urlencoded".to_vec(),
                    ),
                    (
                        "authorization".to_owned(),
                        format!("Basic {basic}").into_bytes(),
                    ),
                ],
                body: body.into_bytes(),
                request_id: "vercel_service.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel client credentials response");

        assert_eq!(response.status(), 503);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert!(response.headers().contains_key("content-security-policy"));
    }

    #[actix_web::test]
    async fn forwards_verified_private_key_jwt_credentials_through_vercel() {
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        snapshot.configuration.issuers[0]
            .scopes
            .push("service.read".to_owned());
        let private = SecretKey::random(&mut OsRng);
        let public = private.public_key().to_encoded_point(false);
        snapshot
            .configuration
            .clients
            .push(robine_id::configuration::Client {
                enabled: true,
                issuer_ids: vec![],
                id: "vercel-assertion-service".to_owned(),
                name: "Vercel assertion service".to_owned(),
                client_type: "confidential".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier: None,
                redirect_uris: vec![],
                post_logout_redirect_uris: vec![],
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                resources: vec![],
                scopes: vec!["service.read".to_owned()],
                grant_types: vec!["client_credentials".to_owned()],
                pkce_required: None,
                nonce_required: None,
                consent_required: None,
                introspection_allowed: false,
                userinfo_signed_response_alg: None,
                require_pushed_authorization_requests: false,
                require_signed_request_object: false,
                request_object_jwks: None,
                required_acr: None,
                max_authentication_age: None,
                actor_token_exchange_allowed: false,
                authorized_actor_clients: vec![],
                authorization_details_types: vec![],
                authentication_method: Some("private_key_jwt".to_owned()),
                secret_reference: None,
                jwks: Some(robine_id::configuration::ClientJwkSet {
                    keys: vec![robine_id::configuration::ClientJwk {
                        kty: "EC".to_owned(),
                        kid: "vercel-client-key".to_owned(),
                        use_: Some("sig".to_owned()),
                        alg: Some("ES256".to_owned()),
                        n: None,
                        e: None,
                        crv: Some("P-256".to_owned()),
                        x: Some(
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .encode(public.x().expect("x coordinate")),
                        ),
                        y: Some(
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .encode(public.y().expect("y coordinate")),
                        ),
                    }],
                }),
                branding: None,
            });
        let issuer = snapshot.configuration.issuers[0]
            .url
            .trim_end_matches('/')
            .to_owned();
        let now = chrono::Utc::now().timestamp();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("vercel-client-key".to_owned());
        let assertion = jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "iss": "vercel-assertion-service",
                "sub": "vercel-assertion-service",
                "aud": format!("{issuer}/token"),
                "iat": now,
                "exp": now + 120,
                "jti": "vercel-assertion-jti"
            }),
            &EncodingKey::from_ec_pem(
                private
                    .to_pkcs8_pem(LineEnding::LF)
                    .expect("PEM")
                    .as_bytes(),
            )
            .expect("private key"),
        )
        .expect("client assertion");
        let worker =
            ActixWorker::start(Application::without_database(snapshot)).expect("Actix worker");
        let body = serde_urlencoded::to_string([
            ("grant_type", "client_credentials"),
            ("client_id", "vercel-assertion-service"),
            ("scope", "service.read"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion.as_str()),
        ])
        .expect("assertion form");
        let response = worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/token".to_owned(),
                headers: vec![(
                    "content-type".to_owned(),
                    b"application/x-www-form-urlencoded".to_vec(),
                )],
                body: body.into_bytes(),
                request_id: "vercel_assertion.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel assertion response");

        assert_eq!(response.status(), 503);
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("response body")
            .to_bytes();
        assert!(
            body.windows(23)
                .any(|value| value == b"temporarily_unavailable")
        );
    }

    #[actix_web::test]
    async fn forwards_verified_client_secret_jwt_credentials_through_vercel() {
        let secret = std::env::var("PATH").expect("test PATH");
        assert!(secret.len() >= 32, "test PATH must be a strong HS256 key");
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        snapshot.configuration.issuers[0]
            .scopes
            .push("service.read".to_owned());
        snapshot
            .configuration
            .clients
            .push(robine_id::configuration::Client {
                enabled: true,
                issuer_ids: vec![],
                id: "vercel-secret-assertion-service".to_owned(),
                name: "Vercel secret assertion service".to_owned(),
                client_type: "confidential".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier: None,
                redirect_uris: vec![],
                post_logout_redirect_uris: vec![],
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                resources: vec![],
                scopes: vec!["service.read".to_owned()],
                grant_types: vec!["client_credentials".to_owned()],
                pkce_required: None,
                nonce_required: None,
                consent_required: None,
                introspection_allowed: false,
                userinfo_signed_response_alg: None,
                require_pushed_authorization_requests: false,
                require_signed_request_object: false,
                request_object_jwks: None,
                required_acr: None,
                max_authentication_age: None,
                actor_token_exchange_allowed: false,
                authorized_actor_clients: vec![],
                authorization_details_types: vec![],
                authentication_method: Some("client_secret_jwt".to_owned()),
                secret_reference: Some(serde_json::json!({
                    "provider": "env",
                    "key": "PATH"
                })),
                jwks: None,
                branding: None,
            });
        let issuer = snapshot.configuration.issuers[0]
            .url
            .trim_end_matches('/')
            .to_owned();
        let now = chrono::Utc::now().timestamp();
        let assertion = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "iss": "vercel-secret-assertion-service",
                "sub": "vercel-secret-assertion-service",
                "aud": format!("{issuer}/token"),
                "exp": now + 120,
                "jti": "vercel-secret-assertion-jti"
            }),
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("client secret assertion");
        let worker =
            ActixWorker::start(Application::without_database(snapshot)).expect("Actix worker");
        let body = serde_urlencoded::to_string([
            ("grant_type", "client_credentials"),
            ("client_id", "vercel-secret-assertion-service"),
            ("scope", "service.read"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion.as_str()),
        ])
        .expect("assertion form");
        let response = worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/token".to_owned(),
                headers: vec![(
                    "content-type".to_owned(),
                    b"application/x-www-form-urlencoded".to_vec(),
                )],
                body: body.into_bytes(),
                request_id: "vercel_secret_assertion.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel client secret assertion response");

        assert_eq!(response.status(), 503);
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("response body")
            .to_bytes();
        assert!(
            body.windows(23)
                .any(|value| value == b"temporarily_unavailable")
        );
    }

    #[actix_web::test]
    async fn forwards_verified_signed_request_objects_through_vercel() {
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        let private = Ed25519SigningKey::generate(&mut OsRng);
        snapshot
            .configuration
            .clients
            .push(robine_id::configuration::Client {
                enabled: true,
                issuer_ids: vec![],
                id: "vercel-request-object-client".to_owned(),
                name: "Vercel request object client".to_owned(),
                client_type: "public".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier: None,
                redirect_uris: vec!["https://client.example/callback".to_owned()],
                post_logout_redirect_uris: vec![],
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                resources: vec![],
                scopes: vec!["openid".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                pkce_required: Some(true),
                nonce_required: Some(true),
                consent_required: Some(false),
                introspection_allowed: false,
                userinfo_signed_response_alg: None,
                require_pushed_authorization_requests: false,
                require_signed_request_object: true,
                request_object_jwks: Some(robine_id::configuration::ClientJwkSet {
                    keys: vec![robine_id::configuration::ClientJwk {
                        kty: "OKP".to_owned(),
                        kid: "vercel-request-key".to_owned(),
                        use_: Some("sig".to_owned()),
                        alg: Some("EdDSA".to_owned()),
                        n: None,
                        e: None,
                        crv: Some("Ed25519".to_owned()),
                        x: Some(
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .encode(private.verifying_key().to_bytes()),
                        ),
                        y: None,
                    }],
                }),
                required_acr: None,
                max_authentication_age: None,
                actor_token_exchange_allowed: false,
                authorized_actor_clients: vec![],
                authorization_details_types: vec![],
                authentication_method: Some("none".to_owned()),
                secret_reference: None,
                jwks: None,
                branding: None,
            });
        let issuer = snapshot.configuration.issuers[0]
            .url
            .trim_end_matches('/')
            .to_owned();
        let now = chrono::Utc::now().timestamp();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("vercel-request-key".to_owned());
        let request_object = jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "iss": "vercel-request-object-client",
                "aud": issuer,
                "iat": now,
                "exp": now + 120,
                "jti": "vercel-request-object-jti",
                "response_type": "code",
                "client_id": "vercel-request-object-client",
                "redirect_uri": "https://client.example/callback",
                "scope": "openid",
                "state": "vercel-signed-state",
                "nonce": "vercel-signed-nonce",
                "code_challenge": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "code_challenge_method": "S256"
            }),
            &EncodingKey::from_ed_pem(
                private
                    .to_pkcs8_pem(LineEnding::LF)
                    .expect("Ed25519 PEM")
                    .as_bytes(),
            )
            .expect("Ed25519 private key"),
        )
        .expect("request object");
        let query = serde_urlencoded::to_string([
            ("client_id", "vercel-request-object-client"),
            ("request", request_object.as_str()),
        ])
        .expect("authorization query");
        let worker =
            ActixWorker::start(Application::without_database(snapshot)).expect("Actix worker");
        let unsigned = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/default/authorize?response_type=code&client_id=vercel-request-object-client&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid&state=unsigned&nonce=unsigned&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_unsigned_request_object.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("unsigned request-object policy response");
        assert_eq!(unsigned.status(), 302);
        assert!(
            unsigned
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("error=invalid_request"))
        );
        let unsigned_par_body = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", "vercel-request-object-client"),
            ("redirect_uri", "https://client.example/callback"),
            ("scope", "openid"),
            ("state", "unsigned-par"),
            ("nonce", "unsigned-par"),
            (
                "code_challenge",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("code_challenge_method", "S256"),
        ])
        .expect("unsigned PAR form");
        let unsigned_par = worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/par".to_owned(),
                headers: vec![(
                    "content-type".to_owned(),
                    b"application/x-www-form-urlencoded".to_vec(),
                )],
                body: unsigned_par_body.into_bytes(),
                request_id: "vercel_unsigned_par_request_object.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("unsigned PAR request-object policy response");
        assert_eq!(unsigned_par.status(), 400);
        let unsigned_par = http_body_util::BodyExt::collect(unsigned_par.into_body())
            .await
            .expect("unsigned PAR body")
            .to_bytes();
        assert!(
            std::str::from_utf8(&unsigned_par)
                .expect("UTF-8 OAuth error")
                .contains("\"error\":\"invalid_request\"")
        );
        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: format!("/default/authorize?{query}"),
                headers: vec![],
                body: vec![],
                request_id: "vercel_request_object.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel request object response");

        assert_eq!(response.status(), 503);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("response body")
            .to_bytes();
        assert!(
            body.windows(23)
                .any(|value| value == b"temporarily_unavailable")
        );
    }

    #[actix_web::test]
    async fn preserves_form_post_errors_and_their_dynamic_csp_through_vercel() {
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        let client = snapshot
            .client("rust-development-client")
            .expect("development client")
            .clone();
        snapshot.configuration.clients = vec![client];
        let query = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", "rust-development-client"),
            ("redirect_uri", "http://localhost:4002/callback"),
            ("scope", "openid forbidden"),
            ("state", "vercel-form-post-state"),
            ("nonce", "vercel-form-post-nonce"),
            (
                "code_challenge",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("code_challenge_method", "S256"),
            ("response_mode", "form_post"),
            ("ui_locales", "fr-FR"),
        ])
        .expect("form_post query");
        let worker =
            ActixWorker::start(Application::without_database(snapshot)).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: format!("/default/authorize?{query}"),
                headers: vec![],
                body: vec![],
                request_id: "vercel_form_post.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel form_post response");

        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get("content-language")
                .and_then(|value| value.to_str().ok()),
            Some("fr")
        );
        assert!(
            response
                .headers()
                .get("content-security-policy")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("form-action http://localhost:4002;"))
        );
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("form_post response body")
            .to_bytes();
        let body = std::str::from_utf8(&body).expect("UTF-8 form_post response");
        assert!(body.contains("name=\"error\" value=\"invalid_scope\""));
        assert!(body.contains("name=\"state\" value=\"vercel-form-post-state\""));
        assert!(body.contains("data-auto-submit"));
        assert!(body.contains("<html lang=\"fr\">"));
        assert!(body.contains("Continuer vers votre application"));
    }

    #[actix_web::test]
    async fn forwards_device_authorization_and_verification_through_vercel() {
        let snapshot = Snapshot::load().expect("development configuration should load");
        assert!(snapshot.client("rust-device-development-client").is_some());
        let worker =
            ActixWorker::start(Application::without_database(snapshot)).expect("Actix worker");

        let page = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/default/device?user_code=BCDF-GHJK".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_device_page.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel device page response");
        assert_eq!(page.status(), 200);
        assert!(page.headers().contains_key("set-cookie"));
        let page_body = http_body_util::BodyExt::collect(page.into_body())
            .await
            .expect("device page body")
            .to_bytes();
        let page_body = std::str::from_utf8(&page_body).expect("UTF-8 device page");
        assert!(page_body.contains("id=\"device-code-form\""));
        assert!(page_body.contains("value=\"BCDF-GHJK\""));

        let form = serde_urlencoded::to_string([
            ("client_id", "rust-device-development-client"),
            ("scope", "openid profile"),
        ])
        .expect("device authorization form");
        let response = worker
            .dispatch(FunctionRequest {
                method: "POST".to_owned(),
                uri: "/default/device_authorization".to_owned(),
                headers: vec![(
                    "content-type".to_owned(),
                    b"application/x-www-form-urlencoded".to_vec(),
                )],
                body: form.into_bytes(),
                request_id: "vercel_device_authorization.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel device authorization response");
        assert_eq!(response.status(), 503);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    #[actix_web::test]
    async fn requires_an_explicit_configuration_only_on_vercel() {
        assert!(!vercel_configuration_explicit(true, false, false));
        assert!(vercel_configuration_explicit(true, true, false));
        assert!(vercel_configuration_explicit(true, false, true));
        assert!(vercel_configuration_explicit(false, false, false));
    }
}
