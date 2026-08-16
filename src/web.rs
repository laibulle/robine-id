use crate::{
    Application,
    database::AccessGrant,
    protocol::{AuthorizationGrant, AuthorizationRequest, DiscoveryDocument},
    tokens,
};
use actix_web::{
    HttpRequest, HttpResponse, Responder,
    cookie::{Cookie, SameSite},
    http::StatusCode,
    web,
};
use askama::Template;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const APP_CSS: &str = include_str!("../assets/css/app.css");
const BRAND_MARK: &[u8] = include_bytes!("../priv/static/images/brand/robine-mark.png");
const APP_JS: &str = r#"document.addEventListener("click", event => {
  const toggle = event.target.closest("[data-password-toggle]");
  if (!toggle) return;
  const input = toggle.parentElement.querySelector("input");
  const revealing = input.type === "password";
  input.type = revealing ? "text" : "password";
  toggle.textContent = revealing ? "Hide" : "Show";
  toggle.setAttribute("aria-label", revealing ? "Hide password" : "Show password");
});"#;

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    revision: &'a str,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    client_name: &'a str,
    request: &'a AuthorizationRequest,
    csrf_token: &'a str,
    error: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "protocol_error.html")]
struct ProtocolErrorTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    message: &'a str,
}

pub fn configure(configuration: &mut web::ServiceConfig) {
    configuration
        .route("/", web::get().to(home))
        .route("/health/live", web::get().to(live))
        .route("/health/ready", web::get().to(ready))
        .route("/assets/app.css", web::get().to(css))
        .route("/assets/app.js", web::get().to(js))
        .route("/images/brand/robine-mark.png", web::get().to(brand_mark))
        .route(
            "/{issuer_id}/.well-known/openid-configuration",
            web::get().to(discovery),
        )
        .route("/{issuer_id}/jwks.json", web::get().to(jwks))
        .route("/{issuer_id}/authorize", web::get().to(authorize))
        .route("/{issuer_id}/authorize", web::post().to(authenticate))
        .route("/{issuer_id}/token", web::post().to(exchange_token))
        .route("/{issuer_id}/userinfo", web::get().to(user_info))
        .default_service(web::to(not_found));
}

#[derive(Deserialize)]
struct LoginForm {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    nonce: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    csrf_token: String,
    identifier: String,
    password: String,
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: String,
    code_verifier: Option<String>,
}

pub fn secure<B>(response: &mut HttpResponse<B>) {
    let headers = response.headers_mut();
    headers.insert(
        actix_web::http::header::X_CONTENT_TYPE_OPTIONS,
        actix_web::http::header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        actix_web::http::header::X_FRAME_OPTIONS,
        actix_web::http::header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        actix_web::http::header::CONTENT_SECURITY_POLICY,
        actix_web::http::header::HeaderValue::from_static(
            "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data: https:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
}

async fn home(application: web::Data<Application>) -> impl Responder {
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.default_issuer() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "not_ready"}),
        );
    };
    let branding = &snapshot.configuration.branding;
    html_response(
        StatusCode::OK,
        HomeTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id: &issuer.id,
            revision: &snapshot.revision,
        }
        .render(),
    )
}

async fn live() -> impl Responder {
    json_response(StatusCode::OK, json!({"status": "live"}))
}

async fn ready(application: web::Data<Application>) -> impl Responder {
    match application.database() {
        Some(database) if database.healthy().await => json_response(
            StatusCode::OK,
            json!({"status": "ready", "revision": application.snapshot().revision}),
        ),
        _ => json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "not_ready", "reason": "database_unavailable"}),
        ),
    }
}

async fn discovery(path: web::Path<String>, application: web::Data<Application>) -> impl Responder {
    match DiscoveryDocument::build(application.snapshot(), &path.into_inner()) {
        Some(document) => {
            let mut response = json_response(StatusCode::OK, json!(document));
            response.headers_mut().insert(
                actix_web::http::header::CACHE_CONTROL,
                actix_web::http::header::HeaderValue::from_static("public, max-age=300"),
            );
            response
        }
        None => json_response(StatusCode::NOT_FOUND, json!({"error": "not_found"})),
    }
}

async fn authorize(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> impl Responder {
    let issuer_id = path.into_inner();
    let branding = &application.snapshot().configuration.branding;
    let authorization = serde_urlencoded::from_str::<AuthorizationRequest>(request.query_string());

    match authorization {
        Ok(authorization) => match authorization.validate(application.snapshot(), &issuer_id) {
            Ok(client) => {
                let csrf_token = random_token();
                let mut response = html_response(
                    StatusCode::OK,
                    LoginTemplate {
                        product_name: &branding.product_name,
                        primary_color: &branding.primary_color,
                        issuer_id: &issuer_id,
                        client_name: if client.name.is_empty() {
                            &client.id
                        } else {
                            &client.name
                        },
                        request: &authorization,
                        csrf_token: &csrf_token,
                        error: None,
                    }
                    .render(),
                );
                let secure_cookie = request
                    .headers()
                    .get("x-forwarded-proto")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|scheme| scheme == "https")
                    || request.connection_info().scheme() == "https";
                let cookie_name = if secure_cookie {
                    "__Host-robine_csrf"
                } else {
                    "robine_csrf"
                };
                let cookie = Cookie::build(cookie_name, csrf_token)
                    .path("/")
                    .http_only(true)
                    .secure(secure_cookie)
                    .same_site(SameSite::Strict)
                    .finish();
                let _ = response.add_cookie(&cookie);
                response
            }
            Err(message) => protocol_error(branding, message),
        },
        Err(_) => protocol_error(
            branding,
            "The authorization request is incomplete or malformed",
        ),
    }
}

async fn authenticate(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<LoginForm>,
    application: web::Data<Application>,
) -> impl Responder {
    let issuer_id = path.into_inner();
    let form = form.into_inner();
    let authorization = AuthorizationRequest {
        response_type: form.response_type,
        client_id: form.client_id,
        redirect_uri: form.redirect_uri,
        scope: form.scope,
        state: form.state,
        nonce: form.nonce,
        code_challenge: form.code_challenge,
        code_challenge_method: form.code_challenge_method,
    };
    let branding = &application.snapshot().configuration.branding;

    let csrf_valid = request
        .cookie("__Host-robine_csrf")
        .or_else(|| request.cookie("robine_csrf"))
        .is_some_and(|cookie| {
            constant_time_eq::constant_time_eq(
                cookie.value().as_bytes(),
                form.csrf_token.as_bytes(),
            )
        });
    if !csrf_valid {
        return protocol_error(branding, "The sign-in form has expired; please start again");
    }

    let client = match authorization.validate(application.snapshot(), &issuer_id) {
        Ok(client) => client,
        Err(message) => return protocol_error(branding, message),
    };
    let Some(database) = application.database() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "database_unavailable"}),
        );
    };
    let remote_address = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::to_owned)
        .or_else(|| request.peer_addr().map(|address| address.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_owned());
    let rate_limit_key = format!(
        "{}:{}",
        remote_address,
        form.identifier.trim().to_lowercase()
    );
    match database
        .allow_authentication_attempt(&rate_limit_key, 5, 60)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return oauth_error(
                StatusCode::TOO_MANY_REQUESTS,
                "slow_down",
                "too many authentication attempts",
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to check authentication rate limit");
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "temporarily_unavailable"}),
            );
        }
    }
    let user = application
        .snapshot()
        .user_by_identifier(&form.identifier)
        .cloned();
    let password = form.password;
    let hash = user
        .as_ref()
        .map(|user| user.password_hash.clone())
        .unwrap_or_else(|| {
            "$2b$12$.JtidA6ZMWny4XaLMozDSOupYHbVNQurj8NkCdM9D3m/g3v3fyXXa".to_owned()
        });
    let valid_password = web::block(move || bcrypt::verify(password, &hash).unwrap_or(false))
        .await
        .unwrap_or(false);

    let Some(user) = user.filter(|_| valid_password) else {
        return html_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            LoginTemplate {
                product_name: &branding.product_name,
                primary_color: &branding.primary_color,
                issuer_id: &issuer_id,
                client_name: if client.name.is_empty() {
                    &client.id
                } else {
                    &client.name
                },
                request: &authorization,
                csrf_token: &form.csrf_token,
                error: Some("The email or password is incorrect."),
            }
            .render(),
        );
    };
    if client.consent_required.unwrap_or(true) {
        return oauth_error(
            StatusCode::NOT_IMPLEMENTED,
            "temporarily_unavailable",
            "the consent step is still handled by the Phoenix runtime",
        );
    }
    let issuer = application
        .snapshot()
        .issuer(&issuer_id)
        .expect("validated issuer");
    let scopes = authorization
        .scope
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let claims = tokens::mapped_claims(application.snapshot(), &user, &scopes);
    let grant = AuthorizationGrant {
        issuer: issuer.url.trim_end_matches('/').to_owned(),
        subject: user.id,
        client_id: authorization.client_id,
        redirect_uri: authorization.redirect_uri.clone(),
        scopes,
        nonce: Some(authorization.nonce),
        code_challenge: authorization.code_challenge,
        claims: json!(claims),
        expires_at: Utc::now() + Duration::seconds(issuer.token_policy.authorization_code_lifetime),
    };

    match database.issue_authorization_code(&grant).await {
        Ok(code) => {
            let mut redirect = match url::Url::parse(&authorization.redirect_uri) {
                Ok(redirect) => redirect,
                Err(_) => return protocol_error(branding, "The redirect URI is invalid"),
            };
            redirect
                .query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", &authorization.state);
            HttpResponse::Found()
                .insert_header((actix_web::http::header::LOCATION, redirect.to_string()))
                .finish()
        }
        Err(error) => {
            tracing::error!(%error, "failed to issue authorization code");
            json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "temporarily_unavailable"}),
            )
        }
    }
}

async fn exchange_token(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<TokenForm>,
    application: web::Data<Application>,
) -> impl Responder {
    let issuer_id = path.into_inner();
    let Some(issuer) = application.snapshot().issuer(&issuer_id) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "unknown issuer");
    };
    let form = form.into_inner();
    if form.grant_type != "authorization_code" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only authorization_code is supported",
        );
    }
    let (basic_id, basic_secret) = basic_credentials(&request);
    let client_id = basic_id.or(form.client_id.clone()).unwrap_or_default();
    let Some(client) = application.snapshot().client(&client_id) else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
    };
    if !authenticate_client(
        client,
        basic_secret.as_deref().or(form.client_secret.as_deref()),
    ) {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
    }
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let grant = match database.consume_authorization_code(&form.code).await {
        Ok(Some(grant)) => grant,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code is invalid",
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to consume authorization code");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "database unavailable",
            );
        }
    };
    if grant.expires_at <= Utc::now()
        || grant.issuer != issuer.url.trim_end_matches('/')
        || grant.client_id != client_id
        || grant.redirect_uri != form.redirect_uri
        || !verify_pkce(
            grant.code_challenge.as_deref(),
            form.code_verifier.as_deref(),
        )
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code validation failed",
        );
    }
    let key = match database.signing_key(&grant.issuer).await {
        Ok(key) => key,
        Err(error) => {
            tracing::error!(%error, "failed to load signing key");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "signing key unavailable",
            );
        }
    };
    let claims = grant.claims.as_object().cloned().unwrap_or_default();
    let now = Utc::now().timestamp();
    let id_token = match tokens::issue_id_token(
        &key,
        &tokens::IdTokenInput {
            issuer: &grant.issuer,
            subject: &grant.subject,
            audience: &grant.client_id,
            nonce: grant.nonce.as_deref(),
            claims: &claims,
            now,
            lifetime: issuer.token_policy.id_token_lifetime,
        },
    ) {
        Ok(token) => token,
        Err(error) => {
            tracing::error!(%error, "failed to sign ID token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token signing failed",
            );
        }
    };
    let access_grant = AccessGrant {
        issuer: grant.issuer,
        subject: grant.subject,
        client_id: grant.client_id,
        scopes: grant.scopes.clone(),
        claims: grant.claims,
        expires_at: Utc::now() + Duration::seconds(issuer.token_policy.access_token_lifetime),
    };
    let access_token = match database.issue_access_token(&access_grant).await {
        Ok(token) => token,
        Err(error) => {
            tracing::error!(%error, "failed to issue access token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token storage failed",
            );
        }
    };
    let mut response = json_response(
        StatusCode::OK,
        json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": issuer.token_policy.access_token_lifetime,
            "scope": grant.scopes.join(" "),
            "id_token": id_token
        }),
    );
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn jwks(path: web::Path<String>, application: web::Data<Application>) -> impl Responder {
    let issuer_id = path.into_inner();
    let Some(issuer) = application.snapshot().issuer(&issuer_id) else {
        return json_response(StatusCode::NOT_FOUND, json!({"error": "not_found"}));
    };
    let Some(database) = application.database() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "database_unavailable"}),
        );
    };
    match database.signing_key(issuer.url.trim_end_matches('/')).await {
        Ok(key) => json_response(
            StatusCode::OK,
            json!({"keys": [{
                "kty": "RSA", "kid": key.kid, "use": "sig", "alg": "RS256", "n": key.modulus, "e": key.exponent
            }]}),
        ),
        Err(error) => {
            tracing::error!(%error, "failed to load JWKS");
            json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "temporarily_unavailable"}),
            )
        }
    }
}

async fn user_info(request: HttpRequest, application: web::Data<Application>) -> impl Responder {
    let token = request
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let (Some(token), Some(database)) = (token, application.database()) else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "bearer token is missing or invalid",
        );
    };
    match database.access_grant(token).await {
        Ok(Some(grant)) if application.snapshot().user(&grant.subject).is_some() => {
            let mut claims = grant.claims.as_object().cloned().unwrap_or_default();
            claims.insert("sub".to_owned(), json!(grant.subject));
            json_response(StatusCode::OK, Value::Object(claims))
        }
        _ => oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "bearer token is missing or invalid",
        ),
    }
}

fn basic_credentials(request: &HttpRequest) -> (Option<String>, Option<String>) {
    let decoded = request
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok())
        .and_then(|value| String::from_utf8(value).ok());
    match decoded.and_then(|value| {
        value
            .split_once(':')
            .map(|(id, secret)| (id.to_owned(), secret.to_owned()))
    }) {
        Some((id, secret)) => (Some(id), Some(secret)),
        None => (None, None),
    }
}

fn authenticate_client(
    client: &crate::configuration::Client,
    provided_secret: Option<&str>,
) -> bool {
    if client.client_type == "public" {
        return provided_secret.is_none();
    }
    let expected = client
        .secret_reference
        .as_ref()
        .and_then(|reference| match reference {
            Value::String(secret) => Some(secret.clone()),
            Value::Object(reference)
                if reference.get("provider").and_then(Value::as_str) == Some("env") =>
            {
                reference
                    .get("key")
                    .and_then(Value::as_str)
                    .and_then(|key| std::env::var(key).ok())
            }
            _ => None,
        });
    match (expected, provided_secret) {
        (Some(expected), Some(provided)) => {
            constant_time_eq::constant_time_eq(expected.as_bytes(), provided.as_bytes())
        }
        _ => false,
    }
}

fn verify_pkce(challenge: Option<&str>, verifier: Option<&str>) -> bool {
    match (challenge, verifier) {
        (None, None | Some("")) => true,
        (Some(challenge), Some(verifier)) => {
            let calculated = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            constant_time_eq::constant_time_eq(challenge.as_bytes(), calculated.as_bytes())
        }
        _ => false,
    }
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    let mut response = json_response(
        status,
        json!({"error": error, "error_description": description}),
    );
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("operating system randomness is unavailable");
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn css() -> impl Responder {
    let portable = APP_CSS
        .split_once("/* This file is for your main application CSS */")
        .map(|(_, css)| css)
        .unwrap_or(APP_CSS);
    let mut response = HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .body(portable);
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("public, max-age=3600"),
    );
    response
}

async fn js() -> impl Responder {
    let mut response = HttpResponse::Ok()
        .content_type("text/javascript; charset=utf-8")
        .body(APP_JS);
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("public, max-age=3600"),
    );
    response
}

async fn brand_mark() -> impl Responder {
    let mut response = HttpResponse::Ok()
        .content_type("image/png")
        .body(BRAND_MARK);
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("public, max-age=86400"),
    );
    response
}

async fn not_found() -> impl Responder {
    json_response(StatusCode::NOT_FOUND, json!({"error": "not_found"}))
}

fn protocol_error(branding: &crate::configuration::Branding, message: &str) -> HttpResponse {
    html_response(
        StatusCode::BAD_REQUEST,
        ProtocolErrorTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            message,
        }
        .render(),
    )
}

fn html_response(status: StatusCode, body: askama::Result<String>) -> HttpResponse {
    match body {
        Ok(body) => HttpResponse::build(status)
            .content_type("text/html; charset=utf-8")
            .body(body),
        Err(error) => {
            tracing::error!(%error, "failed to render template");
            json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "internal_server_error"}),
            )
        }
    }
}

fn json_response(status: StatusCode, body: serde_json::Value) -> HttpResponse {
    HttpResponse::build(status).json(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{Branding, Issuer, RootConfiguration, Snapshot};
    use actix_web::{App, test};

    fn application() -> Application {
        Application::without_database(Snapshot {
            configuration: RootConfiguration {
                schema_version: 1,
                issuers: vec![Issuer {
                    id: "default".to_owned(),
                    url: "https://id.example/default".to_owned(),
                    scopes: vec!["openid".to_owned()],
                    token_policy: crate::configuration::TokenPolicy::default(),
                }],
                clients: vec![],
                branding: Branding::default(),
                users: vec![],
                claims: Default::default(),
            },
            revision: "abc123".to_owned(),
        })
    }

    #[actix_web::test]
    async fn serves_oidc_discovery() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let request = test::TestRequest::get()
            .uri("/default/.well-known/openid-configuration")
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["issuer"], "https://id.example/default");
    }
}
