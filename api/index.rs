use actix_web::{App, HttpResponse, body::MessageBody, body::to_bytes, test, web};
use robine_id::{Application, initialize_tracing, web as robine_web};
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
    let started_at = Instant::now();
    let span = tracing::info_span!("http_request", request_id = %request_id, method = %method);
    async move {
        let (parts, body) = request.into_parts();
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
                    return payload_too_large_response(&request_id);
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
                        let span = tracing::info_span!(
                            "http_request",
                            request_id = %job.input.request_id,
                            method = %job.input.method
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
        let (response, receiver) = oneshot::channel();
        if let Err(error) = self.sender.try_send(WorkerJob { input, response }) {
            let reason = match error {
                mpsc::error::TrySendError::Full(_) => "queue_full",
                mpsc::error::TrySendError::Closed(_) => "worker_unavailable",
            };
            self.application
                .metrics()
                .record_http_response(503, started_at.elapsed());
            tracing::warn!(
                event = "vercel_adapter_rejection",
                outcome = "rejected",
                reason,
                "Vercel request rejected before Actix dispatch"
            );
            return service_unavailable_response(&request_id);
        }
        match receiver.await {
            Ok(Ok(response)) => function_response_to_vercel(response),
            Ok(Err(error)) => {
                self.application
                    .metrics()
                    .record_http_response(503, started_at.elapsed());
                tracing::error!(
                    event = "vercel_adapter_failure",
                    outcome = "failed",
                    diagnostic = %error,
                    "Actix worker could not produce a response"
                );
                service_unavailable_response(&request_id)
            }
            Err(_) => {
                self.application
                    .metrics()
                    .record_http_response(503, started_at.elapsed());
                tracing::error!(
                    event = "vercel_adapter_failure",
                    outcome = "failed",
                    reason = "worker_stopped",
                    "Actix worker stopped before completing a request"
                );
                service_unavailable_response(&request_id)
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

fn payload_too_large_response(request_id: &str) -> Result<Response<ResponseBody>, Error> {
    let mut builder = Response::builder()
        .status(413)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-request-id", request_id)
        .header("cross-origin-resource-policy", "same-origin");
    for &(name, value) in robine_web::SECURITY_HEADERS {
        builder = builder.header(name, value);
    }
    Ok(builder.body(ResponseBody::from(
        serde_json::json!({"error": "payload_too_large"}).to_string(),
    ))?)
}

fn service_unavailable_response(request_id: &str) -> Result<Response<ResponseBody>, Error> {
    let mut builder = Response::builder()
        .status(503)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("retry-after", "1")
        .header("x-request-id", request_id)
        .header("cross-origin-resource-policy", "same-origin");
    for &(name, value) in robine_web::SECURITY_HEADERS {
        builder = builder.header(name, value);
    }
    Ok(builder.body(ResponseBody::from(
        serde_json::json!({"error": "temporarily_unavailable"}).to_string(),
    ))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use rand_core::OsRng;
    use robine_id::Snapshot;
    use rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey, LineEnding},
        traits::PublicKeyParts,
    };

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
        assert!(response.headers().contains_key("content-security-policy"));
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("response body")
            .to_bytes();
        assert_eq!(body, r#"{"status":"live"}"#);

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
    async fn converts_bounded_adapter_rejections_to_secure_responses() {
        let response =
            payload_too_large_response("vercel_limit.123").expect("Vercel rejection response");
        assert_eq!(response.status(), 413);
        assert_eq!(
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("vercel_limit.123")
        );
        assert!(response.headers().contains_key("content-security-policy"));
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
                method: "GET".to_owned(),
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
        assert!(response.headers().contains_key("content-security-policy"));
    }

    #[actix_web::test]
    async fn forwards_public_client_token_preflight_through_vercel() {
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
    }

    #[actix_web::test]
    async fn forwards_jarm_discovery_through_vercel() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let worker = ActixWorker::start(application).expect("Actix worker");
        let response = worker
            .dispatch(FunctionRequest {
                method: "GET".to_owned(),
                uri: "/default/.well-known/openid-configuration".to_owned(),
                headers: vec![],
                body: vec![],
                request_id: "vercel_jarm_discovery.123".to_owned(),
                started_at: Instant::now(),
            })
            .await
            .expect("Vercel discovery response");

        assert_eq!(response.status(), 200);
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
            body["dpop_signing_alg_values_supported"],
            serde_json::json!(["ES256", "RS256"])
        );
        assert_eq!(
            body["response_modes_supported"],
            serde_json::json!(["query", "form_post", "jwt", "query.jwt", "form_post.jwt"])
        );
    }

    #[actix_web::test]
    async fn forwards_pushed_authorization_requests_through_vercel() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
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
        snapshot
            .configuration
            .clients
            .push(robine_id::configuration::Client {
                id: "vercel-service".to_owned(),
                name: "Vercel service".to_owned(),
                client_type: "confidential".to_owned(),
                redirect_uris: vec![],
                post_logout_redirect_uris: vec![],
                resources: vec!["https://api.example/resource".to_owned()],
                scopes: vec!["service.read".to_owned()],
                grant_types: vec!["client_credentials".to_owned()],
                pkce_required: None,
                nonce_required: None,
                consent_required: None,
                introspection_allowed: false,
                require_pushed_authorization_requests: false,
                required_acr: None,
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
        let worker =
            ActixWorker::start(Application::without_database(snapshot)).expect("Actix worker");
        let body = serde_urlencoded::to_string([
            ("grant_type", "client_credentials"),
            ("scope", "service.read"),
        ])
        .expect("client credentials form");
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
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key");
        let public = private.to_public_key();
        snapshot
            .configuration
            .clients
            .push(robine_id::configuration::Client {
                id: "vercel-assertion-service".to_owned(),
                name: "Vercel assertion service".to_owned(),
                client_type: "confidential".to_owned(),
                redirect_uris: vec![],
                post_logout_redirect_uris: vec![],
                resources: vec![],
                scopes: vec!["service.read".to_owned()],
                grant_types: vec!["client_credentials".to_owned()],
                pkce_required: None,
                nonce_required: None,
                consent_required: None,
                introspection_allowed: false,
                require_pushed_authorization_requests: false,
                required_acr: None,
                authorization_details_types: vec![],
                authentication_method: Some("private_key_jwt".to_owned()),
                secret_reference: None,
                jwks: Some(robine_id::configuration::ClientJwkSet {
                    keys: vec![robine_id::configuration::ClientJwk {
                        kty: "RSA".to_owned(),
                        kid: "vercel-client-key".to_owned(),
                        use_: Some("sig".to_owned()),
                        alg: Some("RS256".to_owned()),
                        n: base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(public.n().to_bytes_be()),
                        e: base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(public.e().to_bytes_be()),
                    }],
                }),
                branding: None,
            });
        let issuer = snapshot.configuration.issuers[0]
            .url
            .trim_end_matches('/')
            .to_owned();
        let now = chrono::Utc::now().timestamp();
        let mut header = Header::new(Algorithm::RS256);
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
            &EncodingKey::from_rsa_pem(
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
    async fn forwards_verified_signed_request_objects_through_vercel() {
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA key");
        let public = private.to_public_key();
        snapshot
            .configuration
            .clients
            .push(robine_id::configuration::Client {
                id: "vercel-request-object-client".to_owned(),
                name: "Vercel request object client".to_owned(),
                client_type: "confidential".to_owned(),
                redirect_uris: vec!["https://client.example/callback".to_owned()],
                post_logout_redirect_uris: vec![],
                resources: vec![],
                scopes: vec!["openid".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                pkce_required: Some(true),
                nonce_required: Some(true),
                consent_required: Some(false),
                introspection_allowed: false,
                require_pushed_authorization_requests: false,
                required_acr: None,
                authorization_details_types: vec![],
                authentication_method: Some("private_key_jwt".to_owned()),
                secret_reference: None,
                jwks: Some(robine_id::configuration::ClientJwkSet {
                    keys: vec![robine_id::configuration::ClientJwk {
                        kty: "RSA".to_owned(),
                        kid: "vercel-request-key".to_owned(),
                        use_: Some("sig".to_owned()),
                        alg: Some("RS256".to_owned()),
                        n: base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(public.n().to_bytes_be()),
                        e: base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(public.e().to_bytes_be()),
                    }],
                }),
                branding: None,
            });
        let issuer = snapshot.configuration.issuers[0]
            .url
            .trim_end_matches('/')
            .to_owned();
        let now = chrono::Utc::now().timestamp();
        let mut header = Header::new(Algorithm::RS256);
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
            &EncodingKey::from_rsa_pem(
                private
                    .to_pkcs8_pem(LineEnding::LF)
                    .expect("PEM")
                    .as_bytes(),
            )
            .expect("private key"),
        )
        .expect("request object");
        let query = serde_urlencoded::to_string([
            ("client_id", "vercel-request-object-client"),
            ("request", request_object.as_str()),
        ])
        .expect("authorization query");
        let worker =
            ActixWorker::start(Application::without_database(snapshot)).expect("Actix worker");
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
