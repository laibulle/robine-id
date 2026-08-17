use crate::{
    Application,
    database::{AccessGrant, Database, PendingAuthorization},
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
    logo: Option<&'a str>,
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
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    support_url: Option<&'a str>,
    privacy_url: Option<&'a str>,
    terms_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "protocol_error.html")]
struct ProtocolErrorTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    message: &'a str,
    logo: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    client_name: &'a str,
    scopes: &'a [String],
    transaction: &'a str,
    csrf_token: &'a str,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    support_url: Option<&'a str>,
    privacy_url: Option<&'a str>,
    terms_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "logout.html")]
struct LogoutTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    transaction: &'a str,
    csrf_token: &'a str,
    logo: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "logout_done.html")]
struct LogoutDoneTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    logo: Option<&'a str>,
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
        .route("/{issuer_id}/authorize/consent", web::post().to(consent))
        .route("/{issuer_id}/token", web::post().to(exchange_token))
        .route("/{issuer_id}/userinfo", web::get().to(user_info))
        .route("/{issuer_id}/logout", web::get().to(logout_confirmation))
        .route("/{issuer_id}/logout", web::post().to(logout))
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
    ui_locales: Option<String>,
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

#[derive(Deserialize)]
struct ConsentForm {
    transaction: String,
    csrf_token: String,
    decision: String,
}

#[derive(Deserialize)]
struct LogoutQuery {
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct LogoutForm {
    transaction: String,
    csrf_token: String,
}

pub fn secure<B>(response: &mut HttpResponse<B>) {
    let headers = response.headers_mut();
    if !headers.contains_key("x-request-id")
        && let Ok(request_id) = actix_web::http::header::HeaderValue::from_str(&random_token())
    {
        headers.insert(
            actix_web::http::header::HeaderName::from_static("x-request-id"),
            request_id,
        );
    }
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
    headers.insert(
        actix_web::http::header::STRICT_TRANSPORT_SECURITY,
        actix_web::http::header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        actix_web::http::header::REFERRER_POLICY,
        actix_web::http::header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        actix_web::http::header::HeaderName::from_static("permissions-policy"),
        actix_web::http::header::HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=()",
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
    let branding = snapshot.branding(Some(&issuer.id), None);
    html_response(
        StatusCode::OK,
        HomeTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id: &issuer.id,
            revision: &snapshot.revision,
            logo: branding.logo.as_deref(),
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
            json!({"status": "not_ready"}),
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
    let default_branding = &application.snapshot().configuration.branding;
    let authorization = serde_urlencoded::from_str::<AuthorizationRequest>(request.query_string());

    match authorization {
        Ok(authorization) => match authorization.validate(application.snapshot(), &issuer_id) {
            Ok(client) => {
                let branding = application
                    .snapshot()
                    .branding(Some(&issuer_id), Some(&client.id));
                let messages = branding.messages(authorization.ui_locales.as_deref());
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
                        messages: &messages,
                        logo: branding.logo.as_deref(),
                        support_url: branding.support_url.as_deref(),
                        privacy_url: branding.privacy_url.as_deref(),
                        terms_url: branding.terms_url.as_deref(),
                    }
                    .render(),
                );
                add_csrf_cookie(&mut response, &request, &csrf_token);
                response
            }
            Err(error) => authorization_request_error(
                application.snapshot(),
                default_branding,
                &issuer_id,
                &authorization,
                error,
            ),
        },
        Err(_) => protocol_error(
            default_branding,
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
        ui_locales: form.ui_locales,
    };
    let default_branding = &application.snapshot().configuration.branding;

    if !valid_csrf(&request, &form.csrf_token) {
        return protocol_error(
            default_branding,
            "The sign-in form has expired; please start again",
        );
    }

    let client = match authorization.validate(application.snapshot(), &issuer_id) {
        Ok(client) => client,
        Err(error) => return protocol_error(default_branding, error.description),
    };
    let branding = application
        .snapshot()
        .branding(Some(&issuer_id), Some(&client.id));
    let messages = branding.messages(authorization.ui_locales.as_deref());
    let Some(database) = application.database() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "database_unavailable"}),
        );
    };
    let remote_address = forwarded_headers_trusted()
        .then(|| {
            request
                .headers()
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .flatten()
        .or_else(|| request.peer_addr().map(|address| address.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_owned());
    let rate_limit_key = format!(
        "{}:{}",
        remote_address,
        form.identifier.trim().to_lowercase()
    );
    let rate_limit = &application
        .snapshot()
        .configuration
        .authentication
        .rate_limit;
    match database
        .allow_authentication_attempt(
            &rate_limit_key,
            rate_limit.attempts,
            rate_limit.window_seconds,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                event = "authentication_rate_limit",
                outcome = "rejected",
                issuer_id,
                client_id = %authorization.client_id
            );
            let mut response = html_response(
                StatusCode::TOO_MANY_REQUESTS,
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
                    error: Some("Too many attempts. Please wait before trying again."),
                    messages: &messages,
                    logo: branding.logo.as_deref(),
                    support_url: branding.support_url.as_deref(),
                    privacy_url: branding.privacy_url.as_deref(),
                    terms_url: branding.terms_url.as_deref(),
                }
                .render(),
            );
            if let Ok(value) = actix_web::http::header::HeaderValue::from_str(
                &rate_limit.window_seconds.to_string(),
            ) {
                response
                    .headers_mut()
                    .insert(actix_web::http::header::RETRY_AFTER, value);
            }
            return response;
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
        tracing::warn!(
            event = "authentication",
            outcome = "failure",
            issuer_id,
            client_id = %authorization.client_id,
            reason = "invalid_credentials"
        );
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
                messages: &messages,
                logo: branding.logo.as_deref(),
                support_url: branding.support_url.as_deref(),
                privacy_url: branding.privacy_url.as_deref(),
                terms_url: branding.terms_url.as_deref(),
            }
            .render(),
        );
    };
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
        nonce: (!authorization.nonce.is_empty()).then_some(authorization.nonce),
        code_challenge: authorization.code_challenge,
        claims: json!(claims),
        expires_at: Utc::now() + Duration::seconds(issuer.token_policy.authorization_code_lifetime),
    };

    let session_policy = &application.snapshot().configuration.authentication.session;
    let session = match database
        .start_session(
            &grant.subject,
            session_policy.max_concurrent.max(1),
            session_policy.absolute_timeout.max(1),
        )
        .await
    {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(%error, "failed to start authenticated session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "session storage failed",
            );
        }
    };
    tracing::info!(
        event = "authentication",
        outcome = "success",
        issuer_id,
        client_id = %grant.client_id,
        subject_id = %grant.subject
    );

    if client.consent_required.unwrap_or(true) {
        let transaction = match database
            .issue_pending_authorization(&grant, &authorization.state)
            .await
        {
            Ok(transaction) => transaction,
            Err(error) => {
                tracing::error!(%error, "failed to store pending authorization");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "authorization storage failed",
                );
            }
        };
        let scopes = consent_scopes(&grant.scopes);
        let mut response = html_response(
            StatusCode::OK,
            ConsentTemplate {
                product_name: &branding.product_name,
                primary_color: &branding.primary_color,
                issuer_id: &issuer_id,
                client_name: if client.name.is_empty() {
                    &client.id
                } else {
                    &client.name
                },
                scopes: &scopes,
                transaction: &transaction,
                csrf_token: &form.csrf_token,
                messages: &messages,
                logo: branding.logo.as_deref(),
                support_url: branding.support_url.as_deref(),
                privacy_url: branding.privacy_url.as_deref(),
                terms_url: branding.terms_url.as_deref(),
            }
            .render(),
        );
        add_session_cookie(
            &mut response,
            &request,
            &session,
            session_policy.absolute_timeout,
        );
        return response;
    }

    match authorization_success(database, &grant, &authorization.state).await {
        Ok(mut response) => {
            add_session_cookie(
                &mut response,
                &request,
                &session,
                session_policy.absolute_timeout,
            );
            response
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

async fn consent(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<ConsentForm>,
    application: web::Data<Application>,
) -> impl Responder {
    let issuer_id = path.into_inner();
    let form = form.into_inner();
    let branding = &application.snapshot().configuration.branding;
    if !valid_csrf(&request, &form.csrf_token) {
        return protocol_error(branding, "The consent form has expired; please start again");
    }
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let Some(session) = session_token(&request) else {
        return protocol_error(
            branding,
            "Your sign-in session has expired; please start again",
        );
    };
    let session_policy = &application.snapshot().configuration.authentication.session;
    let subject = match database
        .validate_session(&session, session_policy.idle_timeout.max(1))
        .await
    {
        Ok(Some(subject)) => subject,
        Ok(None) => {
            return protocol_error(
                branding,
                "Your sign-in session has expired; please start again",
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to validate authenticated session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "session storage failed",
            );
        }
    };
    let pending = match database
        .consume_pending_authorization(&form.transaction)
        .await
    {
        Ok(Some(pending)) if pending.expires_at > Utc::now() => pending,
        Ok(_) => return protocol_error(branding, "This authorization request has expired"),
        Err(error) => {
            tracing::error!(%error, "failed to consume pending authorization");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "authorization storage failed",
            );
        }
    };
    let Some(issuer) = application.snapshot().issuer(&issuer_id) else {
        return protocol_error(branding, "The authorization issuer is unknown");
    };
    if pending.issuer != issuer.url.trim_end_matches('/') || pending.subject != subject {
        return protocol_error(branding, "This authorization request is not valid");
    }

    match form.decision.as_str() {
        "approve" => {
            tracing::info!(
                event = "authorization_consent",
                outcome = "approved",
                issuer_id,
                client_id = %pending.client_id,
                subject_id = %pending.subject
            );
            let state = pending.state.clone();
            let grant = AuthorizationGrant::from(pending);
            match authorization_success(database, &grant, &state).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::error!(%error, "failed to issue authorization code");
                    oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "authorization storage failed",
                    )
                }
            }
        }
        "deny" => {
            tracing::info!(
                event = "authorization_consent",
                outcome = "denied",
                issuer_id,
                client_id = %pending.client_id,
                subject_id = %pending.subject
            );
            authorization_denied(&pending)
        }
        _ => protocol_error(branding, "The consent decision is invalid"),
    }
}

async fn logout_confirmation(
    path: web::Path<String>,
    request: HttpRequest,
    query: web::Query<LogoutQuery>,
    application: web::Data<Application>,
) -> impl Responder {
    let issuer_id = path.into_inner();
    let query = query.into_inner();
    let snapshot = application.snapshot();
    let default_branding = &snapshot.configuration.branding;
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return protocol_error(default_branding, "The logout issuer is unknown");
    };
    let branding = snapshot.branding(Some(&issuer_id), None);
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };

    let return_to = match query.post_logout_redirect_uri.as_deref() {
        Some(uri) => {
            let Some(hint) = query.id_token_hint.as_deref() else {
                return protocol_error(
                    &branding,
                    "An ID token hint is required for a post-logout redirect",
                );
            };
            let keys = match database
                .verification_signing_keys(issuer.url.trim_end_matches('/'))
                .await
            {
                Ok(keys) => keys,
                Err(error) => {
                    tracing::error!(%error, "failed to load signing keys for logout");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "signing key unavailable",
                    );
                }
            };
            let claims = keys.iter().find_map(|key| {
                tokens::verify_id_token(
                    hint,
                    key,
                    issuer.url.trim_end_matches('/'),
                    issuer.token_policy.clock_skew.max(0) as u64,
                )
                .ok()
            });
            let Some(claims) = claims else {
                return protocol_error(&branding, "The ID token hint is invalid");
            };
            let Some(client) = snapshot.client(&claims.aud) else {
                return protocol_error(&branding, "The ID token audience is unknown");
            };
            if !client
                .post_logout_redirect_uris
                .iter()
                .any(|registered| registered == uri)
            {
                return protocol_error(&branding, "The post-logout redirect URI is not registered");
            }
            match redirect_with_state(uri, query.state.as_deref()) {
                Some(uri) => Some(uri),
                None => {
                    return protocol_error(&branding, "The post-logout redirect URI is invalid");
                }
            }
        }
        None => None,
    };

    let transaction = match database
        .issue_logout_transaction(return_to.as_deref())
        .await
    {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::error!(%error, "failed to create logout transaction");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "logout storage failed",
            );
        }
    };
    let csrf_token = random_token();
    let mut response = html_response(
        StatusCode::OK,
        LogoutTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id: &issuer_id,
            transaction: &transaction,
            csrf_token: &csrf_token,
            logo: branding.logo.as_deref(),
        }
        .render(),
    );
    add_csrf_cookie(&mut response, &request, &csrf_token);
    response
}

async fn logout(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<LogoutForm>,
    application: web::Data<Application>,
) -> impl Responder {
    let issuer_id = path.into_inner();
    let form = form.into_inner();
    let branding = application.snapshot().branding(Some(&issuer_id), None);
    if !valid_csrf(&request, &form.csrf_token) {
        return protocol_error(&branding, "The logout form has expired; please start again");
    }
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let return_to = match database.consume_logout_transaction(&form.transaction).await {
        Ok(Some(return_to)) => return_to,
        Ok(None) => return protocol_error(&branding, "This logout request has expired"),
        Err(error) => {
            tracing::error!(%error, "failed to consume logout transaction");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "logout storage failed",
            );
        }
    };

    if let Some(session) = session_token(&request)
        && let Err(error) = database.revoke_session(&session).await
    {
        tracing::error!(%error, "failed to revoke session during logout");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "session storage failed",
        );
    }

    let mut response = match return_to {
        Some(uri) => HttpResponse::Found()
            .insert_header((actix_web::http::header::LOCATION, uri))
            .finish(),
        None => html_response(
            StatusCode::OK,
            LogoutDoneTemplate {
                product_name: &branding.product_name,
                primary_color: &branding.primary_color,
                logo: branding.logo.as_deref(),
            }
            .render(),
        ),
    };
    remove_session_cookie(&mut response, &request);
    response
}

impl From<PendingAuthorization> for AuthorizationGrant {
    fn from(pending: PendingAuthorization) -> Self {
        Self {
            issuer: pending.issuer,
            subject: pending.subject,
            client_id: pending.client_id,
            redirect_uri: pending.redirect_uri,
            scopes: pending.scopes,
            nonce: pending.nonce,
            code_challenge: pending.code_challenge,
            claims: pending.claims,
            expires_at: pending.expires_at,
        }
    }
}

async fn authorization_success(
    database: &Database,
    grant: &AuthorizationGrant,
    state: &str,
) -> Result<HttpResponse, sqlx::Error> {
    let code = database.issue_authorization_code(grant).await?;
    let mut redirect = url::Url::parse(&grant.redirect_uri)
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    redirect
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", state);
    Ok(HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, redirect.to_string()))
        .finish())
}

fn authorization_denied(pending: &PendingAuthorization) -> HttpResponse {
    let Ok(mut redirect) = url::Url::parse(&pending.redirect_uri) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect URI is invalid",
        );
    };
    redirect
        .query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("error_description", "The resource owner denied the request")
        .append_pair("state", &pending.state);
    HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, redirect.to_string()))
        .finish()
}

fn authorization_request_error(
    snapshot: &crate::configuration::Snapshot,
    branding: &crate::configuration::Branding,
    issuer_id: &str,
    request: &AuthorizationRequest,
    error: crate::protocol::AuthorizationError,
) -> HttpResponse {
    let trusted_redirect = snapshot.issuer(issuer_id).is_some()
        && snapshot
            .client(&request.client_id)
            .is_some_and(|client| client.redirect_uris.contains(&request.redirect_uri));
    if !trusted_redirect {
        return protocol_error(branding, error.description);
    }
    let Ok(mut redirect) = url::Url::parse(&request.redirect_uri) else {
        return protocol_error(branding, error.description);
    };
    redirect
        .query_pairs_mut()
        .append_pair("error", error.code)
        .append_pair("error_description", error.description);
    if !request.state.is_empty() {
        redirect
            .query_pairs_mut()
            .append_pair("state", &request.state);
    }
    HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, redirect.to_string()))
        .finish()
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
    if basic_id.is_some()
        && form.client_id.is_some()
        && basic_id.as_deref() != form.client_id.as_deref()
    {
        return invalid_client_response();
    }
    let client_id = basic_id
        .clone()
        .or(form.client_id.clone())
        .unwrap_or_default();
    let Some(client) = application.snapshot().client(&client_id) else {
        return invalid_client_response();
    };
    if !authenticate_client(
        client,
        basic_id.as_deref(),
        basic_secret.as_deref(),
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    ) {
        return invalid_client_response();
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
    response.headers_mut().insert(
        actix_web::http::header::PRAGMA,
        actix_web::http::header::HeaderValue::from_static("no-cache"),
    );
    tracing::info!(
        event = "token_exchange",
        outcome = "success",
        issuer_id,
        client_id,
        subject_id = %access_grant.subject
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
    match database
        .public_signing_keys(issuer.url.trim_end_matches('/'))
        .await
    {
        Ok(keys) => {
            let mut response = json_response(
                StatusCode::OK,
                json!({"keys": keys.into_iter().map(|key| json!({
                "kty": "RSA", "kid": key.kid, "use": "sig", "alg": "RS256",
                "n": key.modulus, "e": key.exponent
                })).collect::<Vec<_>>() }),
            );
            response.headers_mut().insert(
                actix_web::http::header::CACHE_CONTROL,
                actix_web::http::header::HeaderValue::from_static("public, max-age=300"),
            );
            response
        }
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
        return invalid_bearer_response();
    };
    match database.access_grant(token).await {
        Ok(Some(grant)) if application.snapshot().user(&grant.subject).is_some() => {
            let mut claims = grant.claims.as_object().cloned().unwrap_or_default();
            claims.insert("sub".to_owned(), json!(grant.subject));
            let mut response = json_response(StatusCode::OK, Value::Object(claims));
            response.headers_mut().insert(
                actix_web::http::header::CACHE_CONTROL,
                actix_web::http::header::HeaderValue::from_static("no-store"),
            );
            response
        }
        _ => invalid_bearer_response(),
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
    basic_id: Option<&str>,
    basic_secret: Option<&str>,
    form_id: Option<&str>,
    form_secret: Option<&str>,
) -> bool {
    if client.client_type == "public" {
        return basic_id.is_none()
            && basic_secret.is_none()
            && form_secret.is_none()
            && form_id == Some(client.id.as_str());
    }
    let expected = client
        .secret_reference
        .as_ref()
        .and_then(|reference| match reference {
            Value::String(secret) if !secret.is_empty() => Some(secret.clone()),
            Value::Object(reference)
                if reference.get("provider").and_then(Value::as_str) == Some("env") =>
            {
                reference
                    .get("key")
                    .and_then(Value::as_str)
                    .and_then(|key| std::env::var(key).ok())
                    .filter(|secret| !secret.is_empty())
            }
            _ => None,
        });
    let provided_secret = match client.authentication_method.as_deref() {
        Some("client_secret_post") if basic_id.is_none() && basic_secret.is_none() => {
            if form_id == Some(client.id.as_str()) {
                form_secret
            } else {
                None
            }
        }
        Some("client_secret_basic") | None
            if form_secret.is_none() && basic_id == Some(client.id.as_str()) =>
        {
            basic_secret
        }
        _ => None,
    };
    match (expected, provided_secret) {
        (Some(expected), Some(provided)) => {
            constant_time_eq::constant_time_eq(expected.as_bytes(), provided.as_bytes())
        }
        _ => false,
    }
}

fn invalid_client_response() -> HttpResponse {
    let mut response = oauth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "client authentication failed",
    );
    response.headers_mut().insert(
        actix_web::http::header::WWW_AUTHENTICATE,
        actix_web::http::header::HeaderValue::from_static("Basic realm=\"token\""),
    );
    response
}

fn invalid_bearer_response() -> HttpResponse {
    let mut response = oauth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "bearer token is missing or invalid",
    );
    response.headers_mut().insert(
        actix_web::http::header::WWW_AUTHENTICATE,
        actix_web::http::header::HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    response
}

fn consent_scopes(scopes: &[String]) -> Vec<String> {
    scopes
        .iter()
        .map(|scope| match scope.as_str() {
            "openid" => "Confirm your identity".to_owned(),
            "profile" => "View your name and profile information".to_owned(),
            "email" => "View your email address".to_owned(),
            scope => format!("Access {scope}"),
        })
        .collect()
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

fn secure_request(request: &HttpRequest) -> bool {
    (forwarded_headers_trusted()
        && request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .is_some_and(|scheme| scheme.trim() == "https"))
        || request.connection_info().scheme() == "https"
}

fn forwarded_headers_trusted() -> bool {
    std::env::var("TRUST_PROXY_HEADERS")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
        || std::env::var_os("VERCEL").is_some()
}

fn valid_csrf(request: &HttpRequest, submitted: &str) -> bool {
    request
        .cookie("__Host-robine_csrf")
        .or_else(|| request.cookie("robine_csrf"))
        .is_some_and(|cookie| {
            constant_time_eq::constant_time_eq(cookie.value().as_bytes(), submitted.as_bytes())
        })
}

fn add_csrf_cookie(response: &mut HttpResponse, request: &HttpRequest, token: &str) {
    let secure = secure_request(request);
    let name = if secure {
        "__Host-robine_csrf"
    } else {
        "robine_csrf"
    };
    let cookie = Cookie::build(name, token.to_owned())
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .finish();
    let _ = response.add_cookie(&cookie);
}

fn session_token(request: &HttpRequest) -> Option<String> {
    request
        .cookie("__Host-robine_session")
        .or_else(|| request.cookie("robine_session"))
        .map(|cookie| cookie.value().to_owned())
}

fn add_session_cookie(
    response: &mut HttpResponse,
    request: &HttpRequest,
    token: &str,
    lifetime_seconds: i64,
) {
    let secure = secure_request(request);
    let name = if secure {
        "__Host-robine_session"
    } else {
        "robine_session"
    };
    let cookie = Cookie::build(name, token.to_owned())
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(actix_web::cookie::time::Duration::seconds(
            lifetime_seconds.max(1),
        ))
        .finish();
    let _ = response.add_cookie(&cookie);
}

fn remove_session_cookie(response: &mut HttpResponse, request: &HttpRequest) {
    let secure = secure_request(request);
    let name = if secure {
        "__Host-robine_session"
    } else {
        "robine_session"
    };
    let mut cookie = Cookie::build(name, "")
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .finish();
    cookie.make_removal();
    let _ = response.add_cookie(&cookie);
}

fn redirect_with_state(uri: &str, state: Option<&str>) -> Option<String> {
    let mut redirect = url::Url::parse(uri).ok()?;
    if let Some(state) = state {
        redirect.query_pairs_mut().append_pair("state", state);
    }
    Some(redirect.to_string())
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
    response.headers_mut().insert(
        actix_web::http::header::PRAGMA,
        actix_web::http::header::HeaderValue::from_static("no-cache"),
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
            logo: branding.logo.as_deref(),
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
                    branding: None,
                }],
                clients: vec![],
                branding: Branding::default(),
                users: vec![],
                claims: Default::default(),
                authentication: Default::default(),
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

    #[actix_web::test]
    async fn security_headers_include_a_correlation_identifier() {
        let mut response = HttpResponse::Ok().finish();
        secure(&mut response);

        assert!(response.headers().contains_key("x-request-id"));
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::REFERRER_POLICY)
                .and_then(|value| value.to_str().ok()),
            Some("no-referrer")
        );
    }

    #[actix_web::test]
    async fn enforces_the_configured_confidential_client_secret_transport() {
        let client = crate::configuration::Client {
            id: "confidential".to_owned(),
            name: "Confidential".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://app.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            scopes: vec!["openid".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            pkce_required: Some(false),
            nonce_required: Some(false),
            consent_required: Some(false),
            authentication_method: Some("client_secret_post".to_owned()),
            secret_reference: Some(json!("correct-secret")),
            branding: None,
        };

        assert!(authenticate_client(
            &client,
            None,
            None,
            Some("confidential"),
            Some("correct-secret")
        ));
        assert!(!authenticate_client(
            &client,
            Some("confidential"),
            Some("correct-secret"),
            None,
            None
        ));
    }
}
