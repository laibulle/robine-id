use crate::{
    Application,
    configuration::DEVICE_CODE_GRANT,
    database::{
        AccessGrant, Database, DeviceAuthorization, DeviceAuthorizationDecision,
        DeviceAuthorizationRequest, DevicePoll, PendingAuthorization, RefreshGrant,
        RefreshRotation, RefreshTokenSelection, SigningKey,
    },
    metrics::{DeviceAuthorizationOutcome, MfaOutcome, TokenGrant},
    protocol::{
        AuthorizationGrant, AuthorizationRequest, DiscoveryDocument, ProtectedResourceMetadata,
        authorization_details_subset, validated_authorization_details,
    },
    tokens,
};
use actix_web::{
    HttpRequest, HttpResponse, Responder,
    cookie::{Cookie, SameSite},
    http::StatusCode,
    middleware, web,
};
use askama::Template;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const APP_CSS: &str = include_str!("../assets/css/app.css");
const BRAND_MARK: &[u8] = include_bytes!("../priv/static/images/brand/robine-mark.png");
const BRAND_MARK_DARK: &[u8] = include_bytes!("../priv/static/images/brand/robine-mark-dark.png");
const LEGACY_LOGO: &[u8] = include_bytes!("../priv/static/images/logo.svg");
const FAVICON: &[u8] = include_bytes!("../priv/static/favicon.ico");
const ROBOTS_TXT: &[u8] = include_bytes!("../priv/static/robots.txt");
const MAX_AUTHORIZATION_QUERY_BYTES: usize = 16 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 320;
const MAX_BCRYPT_PASSWORD_BYTES: usize = 72;
const MAX_LOGOUT_HINT_BYTES: usize = 16 * 1024;
const MAX_ACCESS_TOKEN_BYTES: usize = 12 * 1024;
const PUSHED_REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const MAX_ACTOR_CHAIN_DEPTH: usize = 8;
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    (
        "content-security-policy",
        "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data: https:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    ),
    ("referrer-policy", "no-referrer"),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    ),
    ("x-permitted-cross-domain-policies", "none"),
    ("x-robots-tag", "noindex, nofollow, noarchive"),
];
const APP_JS: &str = r#"document.addEventListener("click", event => {
  const toggle = event.target.closest("[data-password-toggle]");
  if (!toggle) return;
  const input = toggle.parentElement.querySelector("input");
  const revealing = input.type === "password";
  input.type = revealing ? "text" : "password";
  const label = revealing ? toggle.dataset.hideLabel : toggle.dataset.showLabel;
  toggle.textContent = label;
  toggle.setAttribute("aria-label", label);
});
document.addEventListener("submit", event => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (form.dataset.submitting === "true") {
    event.preventDefault();
    return;
  }
  form.dataset.submitting = "true";
  form.setAttribute("aria-busy", "true");
  const submitter = event.submitter || form.querySelector('button[type="submit"], input[type="submit"]');
  if (submitter) submitter.classList.add("is-submitting");
  form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(control => {
    control.setAttribute("aria-disabled", "true");
  });
});
const errorSummary = document.querySelector("[data-error-summary]");
if (errorSummary) errorSummary.focus();
const autoSubmitForm = document.querySelector("[data-auto-submit]");
if (autoSubmitForm) window.requestAnimationFrame(() => autoSubmitForm.requestSubmit());"#;

const FRONTCHANNEL_JS: &str = r#"const logout = document.querySelector("[data-frontchannel-logout]");
if (logout) {
  const destination = logout.dataset.returnTo;
  const frames = Array.from(logout.querySelectorAll("iframe"));
  let remaining = frames.length;
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    window.location.assign(destination);
  };
  const settled = () => {
    remaining -= 1;
    if (remaining <= 0) finish();
  };
  frames.forEach(frame => {
    frame.addEventListener("load", settled, {once: true});
    frame.addEventListener("error", settled, {once: true});
  });
  window.setTimeout(finish, 1500);
  if (frames.length === 0) finish();
}"#;

const CHECK_SESSION_JS: &str = r#"const root = document.documentElement;
const validationEndpoint = root.dataset.originValidationEndpoint;
const allowedOrigins = new Map();
const tokenPattern = /^[A-Za-z0-9_-]{43}$/;
const browserStateCookie = location.protocol === "https:" ? "__Host-robine_opbs" : "robine_opbs";

const browserState = () => {
  const prefix = `${browserStateCookie}=`;
  const cookie = document.cookie.split("; ").find(value => value.startsWith(prefix));
  return cookie ? cookie.slice(prefix.length) : "";
};

const reply = (event, status) => {
  if (event.source) event.source.postMessage(status, event.origin);
};

const originAllowed = async (clientId, origin) => {
  const key = `${clientId}\u0000${origin}`;
  if (!allowedOrigins.has(key)) {
    const url = new URL(validationEndpoint, location.origin);
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("origin", origin);
    allowedOrigins.set(key, fetch(url, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      headers: {"accept": "text/plain"}
    }).then(response => response.status === 204).catch(() => false));
  }
  return allowedOrigins.get(key);
};

window.addEventListener("message", async event => {
  if (typeof event.data !== "string" || event.data.length > 1024 || event.origin === "null") {
    reply(event, "error");
    return;
  }
  const separator = event.data.lastIndexOf(" ");
  const clientId = event.data.slice(0, separator);
  const sessionState = event.data.slice(separator + 1);
  const stateParts = sessionState.split(".");
  if (separator <= 0 || clientId.length > 256 || stateParts.length !== 2 ||
      !tokenPattern.test(stateParts[0]) || !tokenPattern.test(stateParts[1]) ||
      !globalThis.crypto?.subtle || !(await originAllowed(clientId, event.origin))) {
    reply(event, "error");
    return;
  }
  const opbs = browserState();
  if (opbs !== "" && !tokenPattern.test(opbs)) {
    reply(event, "error");
    return;
  }
  const input = `${clientId} ${event.origin} ${opbs} ${stateParts[1]}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  const encoded = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  reply(event, `${encoded}.${stateParts[1]}` === sessionState ? "unchanged" : "changed");
});"#;

#[derive(Clone, Copy)]
struct EmbeddableResponse;

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    revision: &'a str,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "docs.html")]
struct DocsTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    client_name: &'a str,
    transaction: &'a str,
    csrf_token: &'a str,
    identifier: &'a str,
    has_error: bool,
    error: Option<&'a str>,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
    support_url: Option<&'a str>,
    privacy_url: Option<&'a str>,
    terms_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "totp.html")]
struct TotpTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    client_name: &'a str,
    transaction: &'a str,
    form_action: &'a str,
    transaction_field: &'a str,
    action_value: Option<&'a str>,
    csrf_token: &'a str,
    has_error: bool,
    error: Option<&'a str>,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
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
    request_id: &'a str,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "form_post.html")]
struct FormPostTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    redirect_uri: &'a str,
    parameters: &'a [(&'a str, &'a str)],
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    client_name: &'a str,
    scopes: &'a [String],
    authorization_details: &'a [ConsentAuthorizationDetail],
    transaction: &'a str,
    csrf_token: &'a str,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
    support_url: Option<&'a str>,
    privacy_url: Option<&'a str>,
    terms_url: Option<&'a str>,
}

struct ConsentAuthorizationDetail {
    name: String,
    payload: String,
}

#[derive(Template)]
#[template(path = "device_code.html")]
struct DeviceCodeTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    user_code: &'a str,
    csrf_token: &'a str,
    has_error: bool,
    error: Option<&'a str>,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
    support_url: Option<&'a str>,
    privacy_url: Option<&'a str>,
    terms_url: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "device_confirm.html")]
struct DeviceConfirmTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    client_name: &'a str,
    user_code: &'a str,
    scopes: &'a [String],
    authorization_details: &'a [ConsentAuthorizationDetail],
    transaction: &'a str,
    csrf_token: &'a str,
    authenticated: bool,
    identifier: &'a str,
    has_error: bool,
    error: Option<&'a str>,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "device_done.html")]
struct DeviceDoneTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    approved: bool,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "logout.html")]
struct LogoutTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    issuer_id: &'a str,
    transaction: &'a str,
    csrf_token: &'a str,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "logout_done.html")]
struct LogoutDoneTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "frontchannel_logout.html")]
struct FrontchannelLogoutTemplate<'a> {
    product_name: &'a str,
    primary_color: &'a str,
    destination: &'a str,
    logout_uris: &'a [String],
    messages: &'a crate::configuration::UiMessages,
    logo: Option<&'a str>,
    favicon: Option<&'a str>,
    font_family: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "check_session.html")]
struct CheckSessionTemplate<'a> {
    origin_validation_endpoint: &'a str,
}

pub fn configure(configuration: &mut web::ServiceConfig) {
    macro_rules! compressed_get {
        ($path:expr, $handler:expr) => {
            web::resource($path)
                .wrap(middleware::Compress::default())
                .route(web::get().to($handler))
        };
    }
    macro_rules! compressed_get_head {
        ($path:expr, $handler:expr) => {
            web::resource($path)
                .wrap(middleware::Compress::default())
                .route(web::get().to($handler))
                .route(web::head().to($handler))
        };
    }
    macro_rules! compressed_metadata {
        ($path:expr, $handler:expr) => {
            web::resource($path)
                .wrap(middleware::Compress::default())
                .route(web::get().to($handler))
                .route(web::head().to($handler))
                .route(web::method(actix_web::http::Method::OPTIONS).to(public_metadata_options))
        };
    }

    configuration
        .app_data(
            web::FormConfig::default()
                .limit(16 * 1024)
                .error_handler(form_rejection),
        )
        .app_data(web::PayloadConfig::new(16 * 1024))
        .app_data(web::QueryConfig::default().error_handler(query_rejection))
        .service(compressed_get!("/", home))
        .service(compressed_get!("/docs", docs))
        .service(compressed_get_head!("/health/live", live))
        .service(compressed_get_head!("/health/ready", ready))
        .service(compressed_get!("/metrics", metrics))
        .service(compressed_metadata!("/.well-known/webfinger", webfinger))
        .service(compressed_metadata!(
            "/.well-known/openid-configuration/{issuer_id}",
            discovery
        ))
        .service(compressed_metadata!(
            "/.well-known/oauth-protected-resource/{issuer_id}/userinfo",
            protected_resource_metadata
        ))
        .service(compressed_get_head!("/assets/app.css", css))
        .service(compressed_get_head!("/assets/app.js", js))
        .service(compressed_get_head!(
            "/assets/frontchannel.js",
            frontchannel_js
        ))
        .service(compressed_get_head!(
            "/assets/check-session.js",
            check_session_js
        ))
        .service(compressed_get_head!(
            "/images/brand/robine-mark.png",
            brand_mark
        ))
        .service(compressed_get_head!(
            "/images/brand/robine-mark-dark.png",
            brand_mark_dark
        ))
        .service(compressed_get_head!("/images/logo.svg", legacy_logo))
        .service(compressed_get_head!("/favicon.ico", favicon))
        .service(compressed_get_head!("/robots.txt", robots))
        .service(compressed_metadata!(
            "/{issuer_id}/.well-known/openid-configuration",
            discovery
        ))
        .service(compressed_metadata!(
            "/.well-known/oauth-authorization-server/{issuer_id}",
            oauth_authorization_server_metadata
        ))
        .service(compressed_metadata!(
            "/{issuer_id}/.well-known/oauth-authorization-server",
            oauth_authorization_server_metadata
        ))
        .service(compressed_metadata!("/{issuer_id}/jwks.json", jwks))
        .service(compressed_get!("/{issuer_id}/check-session", check_session))
        .service(compressed_get!(
            "/{issuer_id}/check-session/origin",
            check_session_origin
        ))
        .service(
            web::resource("/{issuer_id}/authorize")
                .route(web::get().to(authorize))
                .route(web::post().to(authorize_post))
                .default_service(web::to(get_post_method_not_allowed)),
        )
        .service(
            web::resource("/{issuer_id}/authorize/consent")
                .route(web::post().to(consent))
                .default_service(web::to(post_method_not_allowed)),
        )
        .service(
            web::resource("/{issuer_id}/par")
                .route(web::post().to(push_authorization))
                .route(web::method(actix_web::http::Method::OPTIONS).to(token_options))
                .default_service(web::to(post_options_method_not_allowed)),
        )
        .service(
            web::resource("/{issuer_id}/device_authorization")
                .route(web::post().to(device_authorization))
                .default_service(web::to(post_method_not_allowed)),
        )
        .service(
            web::resource("/{issuer_id}/device")
                .route(web::get().to(device_verification))
                .route(web::post().to(device_interaction))
                .default_service(web::to(get_post_method_not_allowed)),
        )
        .service(
            web::resource("/{issuer_id}/token")
                .route(web::post().to(exchange_token))
                .route(web::method(actix_web::http::Method::OPTIONS).to(token_options))
                .default_service(web::to(post_options_method_not_allowed)),
        )
        .service(
            web::resource("/{issuer_id}/introspect")
                .route(web::post().to(introspect_token))
                .default_service(web::to(post_method_not_allowed)),
        )
        .service(
            web::resource("/{issuer_id}/revoke")
                .route(web::post().to(revoke_token))
                .route(web::method(actix_web::http::Method::OPTIONS).to(revocation_options))
                .default_service(web::to(post_options_method_not_allowed)),
        )
        .service(
            web::resource("/{issuer_id}/userinfo")
                .route(web::get().to(user_info))
                .route(web::post().to(user_info))
                .route(web::method(actix_web::http::Method::OPTIONS).to(user_info_options))
                .default_service(web::to(get_post_options_method_not_allowed)),
        )
        .service(
            web::resource("/{issuer_id}/logout")
                .route(web::get().to(logout_confirmation))
                .route(web::post().to(logout))
                .default_service(web::to(get_post_method_not_allowed)),
        )
        .default_service(web::to(not_found));
}

fn form_rejection(
    error: actix_web::error::UrlencodedError,
    request: &HttpRequest,
) -> actix_web::Error {
    tracing::warn!(
        event = "request_rejection",
        outcome = "rejected",
        reason = "malformed_form",
        "request form rejected"
    );
    let mut response = if [
        "/par",
        "/device_authorization",
        "/token",
        "/introspect",
        "/revoke",
    ]
    .iter()
    .any(|suffix| request.path().ends_with(suffix))
    {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the OAuth request is incomplete or malformed",
        )
    } else {
        browser_request_rejection(request, "The submitted form is incomplete or malformed")
    };
    if let Some(application) = request.app_data::<web::Data<Application>>()
        && let Some((issuer_id, endpoint)) = request
            .path()
            .strip_prefix('/')
            .and_then(|path| path.split_once('/'))
    {
        match endpoint {
            "token" | "par" => add_token_cors(
                &mut response,
                request,
                &application.snapshot(),
                issuer_id,
                None,
            ),
            "revoke" => add_revocation_cors(
                &mut response,
                request,
                &application.snapshot(),
                issuer_id,
                None,
            ),
            _ => {}
        }
    }
    actix_web::error::InternalError::from_response(error, response).into()
}

fn query_rejection(
    error: actix_web::error::QueryPayloadError,
    request: &HttpRequest,
) -> actix_web::Error {
    tracing::warn!(
        event = "request_rejection",
        outcome = "rejected",
        reason = "malformed_query",
        "request query rejected"
    );
    let response = browser_request_rejection(request, "The request is incomplete or malformed");
    actix_web::error::InternalError::from_response(error, response).into()
}

fn browser_request_rejection(request: &HttpRequest, message: &str) -> HttpResponse {
    let application = request.app_data::<web::Data<Application>>();
    let issuer_id = request.match_info().get("issuer_id");
    let branding = application
        .map(|application| application.snapshot().branding(issuer_id, None))
        .unwrap_or_default();
    protocol_error(&branding, message, &correlation_id(request))
}

#[derive(Deserialize)]
struct AuthorizationPostForm {
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    ui_locales: Option<String>,
    prompt: Option<String>,
    max_age: Option<String>,
    response_mode: Option<String>,
    resource: Option<String>,
    #[serde(rename = "request")]
    request_object: Option<String>,
    request_uri: Option<String>,
    login_hint: Option<String>,
    id_token_hint: Option<String>,
    acr_values: Option<String>,
    claims: Option<String>,
    authorization_details: Option<String>,
    dpop_jkt: Option<String>,
    transaction: Option<String>,
    csrf_token: Option<String>,
    identifier: Option<String>,
    password: Option<String>,
    mfa_transaction: Option<String>,
    totp_code: Option<String>,
}

#[derive(Deserialize)]
struct WebFingerQuery {
    resource: String,
    #[serde(default)]
    rel: Option<String>,
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    device_code: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    authorization_details: Option<String>,
    audience: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    requested_token_type: Option<String>,
    actor_token: Option<String>,
    actor_token_type: Option<String>,
}

#[derive(Deserialize)]
struct DeviceAuthorizationForm {
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    authorization_details: Option<String>,
}

#[derive(Deserialize)]
struct DeviceVerificationQuery {
    #[serde(default)]
    user_code: Option<String>,
}

#[derive(Deserialize)]
struct DeviceInteractionForm {
    action: String,
    csrf_token: String,
    #[serde(default)]
    user_code: Option<String>,
    #[serde(default)]
    transaction: Option<String>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    identifier: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    mfa_transaction: Option<String>,
    #[serde(default)]
    totp_code: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct DeviceTotpPayload {
    device_transaction: String,
    decision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationReferenceRequest {
    client_id: String,
    request_uri: String,
}

#[derive(Deserialize)]
struct PushedAuthorizationForm {
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    nonce: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    #[serde(default)]
    ui_locales: Option<String>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    max_age: Option<String>,
    #[serde(default)]
    response_mode: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default, rename = "request")]
    request_object: Option<String>,
    #[serde(default)]
    request_uri: Option<String>,
    #[serde(default)]
    login_hint: Option<String>,
    #[serde(default)]
    id_token_hint: Option<String>,
    #[serde(default)]
    acr_values: Option<String>,
    #[serde(default)]
    claims: Option<String>,
    #[serde(default)]
    authorization_details: Option<String>,
    #[serde(default)]
    dpop_jkt: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

impl PushedAuthorizationForm {
    fn into_request(
        self,
    ) -> (
        AuthorizationRequest,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        (
            AuthorizationRequest {
                response_type: self.response_type,
                client_id: self.client_id,
                redirect_uri: self.redirect_uri,
                scope: self.scope,
                state: self.state,
                nonce: self.nonce,
                code_challenge: self.code_challenge,
                code_challenge_method: self.code_challenge_method,
                ui_locales: self.ui_locales,
                prompt: self.prompt,
                max_age: self.max_age,
                response_mode: self.response_mode,
                resource: self.resource,
                request_object: self.request_object,
                request_uri: self.request_uri,
                login_hint: self.login_hint,
                id_token_hint: self.id_token_hint,
                acr_values: self.acr_values,
                claims: self.claims,
                authorization_details: self.authorization_details,
                dpop_jkt: self.dpop_jkt,
            }
            .normalize_empty_optional_parameters(),
            self.client_secret,
            self.client_assertion_type,
            self.client_assertion,
        )
    }
}

#[derive(Deserialize)]
struct TokenStatusForm {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
}

#[derive(Deserialize)]
struct ConsentForm {
    transaction: String,
    csrf_token: String,
    decision: String,
}

#[derive(Default, Deserialize)]
struct LogoutRequest {
    id_token_hint: Option<String>,
    logout_hint: Option<String>,
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
    ui_locales: Option<String>,
}

#[derive(Deserialize)]
struct LogoutPostForm {
    transaction: Option<String>,
    csrf_token: Option<String>,
    #[serde(flatten)]
    request: LogoutRequest,
}

impl LogoutRequest {
    fn parameters_absent(&self) -> bool {
        self.id_token_hint.is_none()
            && self.logout_hint.is_none()
            && self.client_id.is_none()
            && self.post_logout_redirect_uri.is_none()
            && self.state.is_none()
            && self.ui_locales.is_none()
    }
}

pub fn secure<B>(response: &mut HttpResponse<B>) {
    let embeddable = response.extensions().get::<EmbeddableResponse>().is_some();
    let headers = response.headers_mut();
    if !headers.contains_key("x-request-id")
        && let Ok(request_id) = actix_web::http::header::HeaderValue::from_str(&random_token())
    {
        headers.insert(
            actix_web::http::header::HeaderName::from_static("x-request-id"),
            request_id,
        );
    }
    for &(name, value) in SECURITY_HEADERS {
        if embeddable && name == "x-frame-options" {
            continue;
        }
        if name == "content-security-policy" && headers.contains_key(name) {
            continue;
        }
        headers.insert(
            actix_web::http::header::HeaderName::from_static(name),
            actix_web::http::header::HeaderValue::from_static(value),
        );
    }
    if !headers.contains_key("cross-origin-resource-policy") {
        headers.insert(
            actix_web::http::header::HeaderName::from_static("cross-origin-resource-policy"),
            actix_web::http::header::HeaderValue::from_static("same-origin"),
        );
    }
}

pub fn correlation_id(request: &HttpRequest) -> String {
    correlation_id_value(
        request
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
    )
}

pub fn correlation_id_value(value: Option<&str>) -> String {
    value
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .map(str::to_owned)
        .unwrap_or_else(random_token)
}

pub fn set_correlation_id<B>(response: &mut HttpResponse<B>, request_id: &str) {
    if let Ok(value) = actix_web::http::header::HeaderValue::from_str(request_id) {
        response.headers_mut().insert(
            actix_web::http::header::HeaderName::from_static("x-request-id"),
            value,
        );
    }
}

async fn home(request: HttpRequest, application: web::Data<Application>) -> impl Responder {
    let clear_session = invalid_existing_session(&request, &application).await;
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.default_issuer() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "not_ready"}),
        );
    };
    let branding = snapshot.branding(Some(&issuer.id), None);
    let mut response = html_response(
        StatusCode::OK,
        HomeTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id: &issuer.id,
            revision: &snapshot.revision,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
        }
        .render(),
    );
    if clear_session {
        remove_session_cookie(&mut response, &request);
    }
    response
}

async fn docs(request: HttpRequest, application: web::Data<Application>) -> impl Responder {
    let clear_session = invalid_existing_session(&request, &application).await;
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.default_issuer() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "not_ready"}),
        );
    };
    let branding = snapshot.branding(Some(&issuer.id), None);
    let mut response = html_response(
        StatusCode::OK,
        DocsTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id: &issuer.id,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
        }
        .render(),
    );
    if clear_session {
        remove_session_cookie(&mut response, &request);
    }
    response
}

async fn live(request: HttpRequest) -> impl Responder {
    health_response(&request, StatusCode::OK, json!({"status": "live"}))
}

async fn ready(request: HttpRequest, application: web::Data<Application>) -> impl Responder {
    let (ready, reason) = if !application.accepting_traffic() {
        (false, "draining")
    } else {
        match application.database() {
            Some(database) if database.healthy().await => (true, "ready"),
            Some(_) => (false, "database_unavailable"),
            None => (false, "database_not_configured"),
        }
    };
    if application.metrics().readiness_changed(ready) {
        if ready {
            tracing::info!(
                event = "readiness",
                outcome = "ready",
                "service became ready"
            );
        } else {
            tracing::warn!(
                event = "readiness",
                outcome = "not_ready",
                reason,
                "service is not ready"
            );
        }
    }
    if ready {
        health_response(
            &request,
            StatusCode::OK,
            json!({"status": "ready", "revision": application.snapshot().revision}),
        )
    } else {
        health_response(
            &request,
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "not_ready"}),
        )
    }
}

fn health_response(request: &HttpRequest, status: StatusCode, body: Value) -> HttpResponse {
    let body = body.to_string();
    let mut response = if request.method() == actix_web::http::Method::HEAD {
        HttpResponse::build(status)
            .content_type("application/json")
            .insert_header((actix_web::http::header::CONTENT_LENGTH, body.len()))
            .finish()
    } else {
        HttpResponse::build(status)
            .content_type("application/json")
            .body(body)
    };
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

async fn metrics(application: web::Data<Application>) -> impl Responder {
    let ready = if application.accepting_traffic() {
        match application.database() {
            Some(database) => database.healthy().await,
            None => false,
        }
    } else {
        false
    };
    let mut response = HttpResponse::Ok()
        .insert_header((
            actix_web::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        ))
        .body(
            application
                .metrics()
                .render(&application.snapshot().revision, ready),
        );
    prevent_caching(&mut response);
    response
}

async fn public_metadata_options() -> impl Responder {
    HttpResponse::NoContent()
        .insert_header((actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
        .insert_header((
            actix_web::http::header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, HEAD, OPTIONS",
        ))
        .insert_header((
            actix_web::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            "If-None-Match",
        ))
        .insert_header(("access-control-max-age", "600"))
        .insert_header((
            actix_web::http::header::CACHE_CONTROL,
            "public, max-age=600",
        ))
        .insert_header(("cross-origin-resource-policy", "cross-origin"))
        .finish()
}

async fn discovery(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> impl Responder {
    let snapshot = application.snapshot();
    match DiscoveryDocument::build(&snapshot, &path.into_inner()) {
        Some(document) => cacheable_json_response(&request, json!(document)),
        None => oauth_error(StatusCode::NOT_FOUND, "invalid_request", "unknown issuer"),
    }
}

async fn oauth_authorization_server_metadata(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> impl Responder {
    let snapshot = application.snapshot();
    match DiscoveryDocument::build(&snapshot, &path.into_inner()) {
        // RFC 8414 allows extension metadata. OIDC discovery remains the canonical superset so
        // the two public metadata endpoints cannot drift.
        Some(document) => cacheable_json_response(&request, json!(document)),
        None => oauth_error(StatusCode::NOT_FOUND, "invalid_request", "unknown issuer"),
    }
}

#[derive(Deserialize)]
struct CheckSessionOriginQuery {
    client_id: String,
    origin: String,
}

async fn check_session(
    path: web::Path<String>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return oauth_error(StatusCode::NOT_FOUND, "invalid_request", "unknown issuer");
    };
    if !url::Url::parse(&issuer.url).is_ok_and(|url| url.scheme() == "https") {
        return oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "session management is unavailable for this issuer",
        );
    }
    let endpoint = format!("/{issuer_id}/check-session/origin");
    let mut response = html_response(
        StatusCode::OK,
        CheckSessionTemplate {
            origin_validation_endpoint: &endpoint,
        }
        .render(),
    );
    response.extensions_mut().insert(EmbeddableResponse);
    response.headers_mut().insert(
        actix_web::http::header::CONTENT_SECURITY_POLICY,
        actix_web::http::header::HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors *; base-uri 'none'",
        ),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("cross-origin-resource-policy"),
        actix_web::http::header::HeaderValue::from_static("cross-origin"),
    );
    response
}

async fn check_session_origin(
    path: web::Path<String>,
    query: web::Query<CheckSessionOriginQuery>,
    application: web::Data<Application>,
) -> HttpResponse {
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&path.into_inner()) else {
        return no_store_empty_response(StatusCode::BAD_REQUEST);
    };
    let supported = url::Url::parse(&issuer.url).is_ok_and(|url| url.scheme() == "https");
    let allowed = supported
        && query.client_id.len() <= 256
        && query.origin.len() <= 512
        && registered_redirect_origin(&snapshot, &issuer.id, &query.client_id, &query.origin);
    if allowed {
        no_store_empty_response(StatusCode::NO_CONTENT)
    } else {
        no_store_empty_response(StatusCode::BAD_REQUEST)
    }
}

fn registered_redirect_origin(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    client_id: &str,
    origin: &str,
) -> bool {
    let Some(candidate) = url::Url::parse(origin).ok().filter(|url| {
        matches!(url.scheme(), "https" | "http")
            && url.origin().ascii_serialization() == origin
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    }) else {
        return false;
    };
    snapshot
        .client_for_issuer(issuer_id, client_id)
        .is_some_and(|client| {
            client.redirect_uris.iter().any(|redirect_uri| {
                url::Url::parse(redirect_uri)
                    .is_ok_and(|redirect| redirect.origin() == candidate.origin())
            })
        })
}

async fn protected_resource_metadata(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> HttpResponse {
    let snapshot = application.snapshot();
    let Some(document) = ProtectedResourceMetadata::build(&snapshot, &path.into_inner()) else {
        return oauth_error(StatusCode::NOT_FOUND, "invalid_request", "unknown resource");
    };
    cacheable_json_response(&request, json!(document))
}

fn user_info_resource_metadata_url(issuer: &crate::configuration::Issuer) -> String {
    let mut url = url::Url::parse(&issuer.url).expect("validated issuer URL is parseable");
    let issuer_path = url.path().trim_end_matches('/');
    url.set_path(&format!(
        "/.well-known/oauth-protected-resource{issuer_path}/userinfo"
    ));
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

const OIDC_ISSUER_REL: &str = "http://openid.net/specs/connect/1.0/issuer";

async fn webfinger(
    query: web::Query<WebFingerQuery>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> HttpResponse {
    let query = query.into_inner();
    if query.resource.is_empty()
        || query.resource.len() > 2_048
        || query.rel.as_deref().is_some_and(|rel| rel.len() > 512)
    {
        return webfinger_response(
            &request,
            StatusCode::BAD_REQUEST,
            json!({"subject": query.resource, "links": []}),
        );
    }

    let snapshot = application.snapshot();
    let Some(issuer) = webfinger_issuer(&snapshot, &query.resource) else {
        return webfinger_response(
            &request,
            StatusCode::NOT_FOUND,
            json!({"subject": query.resource, "links": []}),
        );
    };
    let links = if query
        .rel
        .as_deref()
        .is_none_or(|rel| rel == OIDC_ISSUER_REL)
    {
        vec![json!({"rel": OIDC_ISSUER_REL, "href": issuer})]
    } else {
        vec![]
    };
    webfinger_response(
        &request,
        StatusCode::OK,
        json!({"subject": query.resource, "links": links}),
    )
}

fn webfinger_issuer(snapshot: &crate::configuration::Snapshot, resource: &str) -> Option<String> {
    let parsed_resource = if let Some(account) = resource.strip_prefix("acct:") {
        let authority = account.rsplit_once('@')?.1;
        if authority.contains(['/', '?', '#']) {
            return None;
        }
        url::Url::parse(&format!("https://{authority}/")).ok()?
    } else {
        url::Url::parse(resource).ok()?
    };
    let authority = url_authority(&parsed_resource)?;
    let candidates = snapshot
        .active_issuers()
        .filter_map(|issuer| {
            let issuer_url = url::Url::parse(issuer.url.trim_end_matches('/')).ok()?;
            (url_authority(&issuer_url).as_ref() == Some(&authority))
                .then_some((issuer, issuer_url))
        })
        .collect::<Vec<_>>();

    if !resource.starts_with("acct:") {
        let mut path_matches = candidates
            .iter()
            .filter(|(_, issuer_url)| {
                parsed_resource.path() == issuer_url.path()
                    || parsed_resource
                        .path()
                        .strip_prefix(issuer_url.path().trim_end_matches('/'))
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
            .collect::<Vec<_>>();
        path_matches.sort_by_key(|(_, issuer_url)| std::cmp::Reverse(issuer_url.path().len()));
        if let Some((issuer, _)) = path_matches.first() {
            return Some(issuer.url.trim_end_matches('/').to_owned());
        }
    }

    (candidates.len() == 1).then(|| candidates[0].0.url.trim_end_matches('/').to_owned())
}

fn url_authority(url: &url::Url) -> Option<(String, u16)> {
    Some((
        url.host_str()?.to_ascii_lowercase(),
        url.port_or_known_default()?,
    ))
}

fn webfinger_response(request: &HttpRequest, status: StatusCode, body: Value) -> HttpResponse {
    let body = body.to_string();
    let etag = format!("W/\"{}\"", hex::encode(Sha256::digest(body.as_bytes())));
    let mut response = if request_etag_matches(request, &etag) {
        HttpResponse::NotModified().finish()
    } else if request.method() == actix_web::http::Method::HEAD {
        HttpResponse::build(status)
            .content_type("application/jrd+json")
            .insert_header((actix_web::http::header::CONTENT_LENGTH, body.len()))
            .finish()
    } else {
        HttpResponse::build(status)
            .content_type("application/jrd+json")
            .body(body)
    };
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static(
            "public, max-age=300, s-maxage=300, stale-while-revalidate=60",
        ),
    );
    if let Ok(etag) = actix_web::http::header::HeaderValue::from_str(&etag) {
        response
            .headers_mut()
            .insert(actix_web::http::header::ETAG, etag);
    }
    response.headers_mut().insert(
        actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        actix_web::http::header::HeaderValue::from_static("*"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("cross-origin-resource-policy"),
        actix_web::http::header::HeaderValue::from_static("cross-origin"),
    );
    response
}

async fn authorize(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> impl Responder {
    let issuer_id = path.into_inner();
    let authorization = if request.query_string().len() > MAX_AUTHORIZATION_QUERY_BYTES {
        Err(AuthorizationInputError::Invalid)
    } else if authorization_query_contains_request_uri(request.query_string()) {
        resolve_pushed_authorization(&issuer_id, request.query_string().as_bytes(), &application)
            .await
    } else {
        match serde_urlencoded::from_str::<AuthorizationRequest>(request.query_string())
            .map(AuthorizationRequest::normalize_empty_optional_parameters)
            .map_err(|_| AuthorizationInputError::Invalid)
        {
            Ok(authorization) => {
                match enforce_signed_request_object_policy(&issuer_id, authorization, &application)
                {
                    Ok(authorization) => match resolve_authorization_request_object(
                        &issuer_id,
                        authorization,
                        &application,
                    )
                    .await
                    {
                        Ok(authorization) => enforce_pushed_authorization_policy(
                            &issuer_id,
                            authorization,
                            &application,
                        ),
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    };
    authorization_input_response(&issuer_id, &request, &application, authorization).await
}

async fn authorization_input_response(
    issuer_id: &str,
    request: &HttpRequest,
    application: &Application,
    authorization: Result<AuthorizationRequest, AuthorizationInputError>,
) -> HttpResponse {
    match authorization {
        Ok(authorization) => {
            authorization_response(issuer_id, request, application, Ok(authorization)).await
        }
        Err(AuthorizationInputError::Invalid) => {
            authorization_response(issuer_id, request, application, Err(())).await
        }
        Err(AuthorizationInputError::Unavailable) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "authorization request storage is unavailable",
        ),
        Err(AuthorizationInputError::InvalidRequestObject(request_object)) => {
            let snapshot = application.snapshot();
            let branding = snapshot.branding(Some(issuer_id), Some(&request_object.client_id));
            authorization_request_error(
                application.database(),
                &snapshot,
                &branding,
                issuer_id,
                &request_object,
                crate::protocol::AuthorizationError::new(
                    "invalid_request_object",
                    "The signed authorization request is invalid or has already been used",
                ),
                &correlation_id(request),
            )
            .await
        }
        Err(AuthorizationInputError::PushedAuthorizationRequired(authorization)) => {
            let snapshot = application.snapshot();
            let branding = snapshot.branding(Some(issuer_id), Some(&authorization.client_id));
            authorization_request_error(
                application.database(),
                &snapshot,
                &branding,
                issuer_id,
                &authorization,
                crate::protocol::AuthorizationError::new(
                    "invalid_request",
                    "This client must initiate authorization through the pushed authorization request endpoint",
                ),
                &correlation_id(request),
            )
            .await
        }
        Err(AuthorizationInputError::SignedRequestObjectRequired(authorization)) => {
            let snapshot = application.snapshot();
            let branding = snapshot.branding(Some(issuer_id), Some(&authorization.client_id));
            authorization_request_error(
                application.database(),
                &snapshot,
                &branding,
                issuer_id,
                &authorization,
                crate::protocol::AuthorizationError::new(
                    "invalid_request",
                    "This client requires a signed authorization request object",
                ),
                &correlation_id(request),
            )
            .await
        }
    }
}

enum AuthorizationInputError {
    Invalid,
    Unavailable,
    InvalidRequestObject(Box<AuthorizationRequest>),
    PushedAuthorizationRequired(Box<AuthorizationRequest>),
    SignedRequestObjectRequired(Box<AuthorizationRequest>),
}

fn enforce_signed_request_object_policy(
    issuer_id: &str,
    authorization: AuthorizationRequest,
    application: &Application,
) -> Result<AuthorizationRequest, AuthorizationInputError> {
    let required = application
        .snapshot()
        .client_for_issuer(issuer_id, &authorization.client_id)
        .is_some_and(|client| client.require_signed_request_object);
    if required && authorization.request_object.is_none() {
        Err(AuthorizationInputError::SignedRequestObjectRequired(
            Box::new(authorization),
        ))
    } else {
        Ok(authorization)
    }
}

fn enforce_pushed_authorization_policy(
    issuer_id: &str,
    authorization: AuthorizationRequest,
    application: &Application,
) -> Result<AuthorizationRequest, AuthorizationInputError> {
    let snapshot = application.snapshot();
    let required = snapshot
        .issuer(issuer_id)
        .is_some_and(|issuer| issuer.token_policy.require_pushed_authorization_requests)
        || snapshot
            .client_for_issuer(issuer_id, &authorization.client_id)
            .is_some_and(|client| client.require_pushed_authorization_requests);
    if required {
        Err(AuthorizationInputError::PushedAuthorizationRequired(
            Box::new(authorization),
        ))
    } else {
        Ok(authorization)
    }
}

#[derive(Clone, Copy)]
enum RequestObjectResolutionError {
    Invalid,
    Unavailable,
}

async fn resolve_authorization_request_object(
    issuer_id: &str,
    outer: AuthorizationRequest,
    application: &Application,
) -> Result<AuthorizationRequest, AuthorizationInputError> {
    if outer.request_object.is_none() {
        return Ok(outer);
    }
    let outer_for_error = outer.clone();
    resolve_authorization_request_object_inner(issuer_id, outer, application)
        .await
        .map_err(|error| match error {
            RequestObjectResolutionError::Invalid => {
                AuthorizationInputError::InvalidRequestObject(Box::new(outer_for_error))
            }
            RequestObjectResolutionError::Unavailable => AuthorizationInputError::Unavailable,
        })
}

async fn resolve_authorization_request_object_inner(
    issuer_id: &str,
    outer: AuthorizationRequest,
    application: &Application,
) -> Result<AuthorizationRequest, RequestObjectResolutionError> {
    if outer.client_id.is_empty() || outer.client_id.len() > 256 || outer.request_uri.is_some() {
        return Err(RequestObjectResolutionError::Invalid);
    }
    let snapshot = application.snapshot();
    let issuer = snapshot
        .issuer(issuer_id)
        .ok_or(RequestObjectResolutionError::Invalid)?;
    let client = snapshot
        .client_for_issuer(issuer_id, &outer.client_id)
        .ok_or(RequestObjectResolutionError::Invalid)?;
    let jwks = client
        .request_object_jwks
        .as_ref()
        .or(client.jwks.as_ref())
        .ok_or(RequestObjectResolutionError::Invalid)?;
    let request_object = outer
        .request_object
        .as_deref()
        .ok_or(RequestObjectResolutionError::Invalid)?;
    let clock_skew = u64::try_from(issuer.token_policy.clock_skew).unwrap_or_default();
    let verified = crate::tokens::verify_authorization_request_object(
        request_object,
        jwks,
        &client.id,
        issuer.url.trim_end_matches('/'),
        clock_skew,
        Utc::now().timestamp(),
    )
    .map_err(|_| RequestObjectResolutionError::Invalid)?;
    let resolved = merge_signed_authorization_request(&outer, verified.request)
        .ok_or(RequestObjectResolutionError::Invalid)?;
    let replay_expires_at = verified
        .expires_at
        .saturating_add(i64::try_from(clock_skew).unwrap_or(i64::MAX));
    let expires_at = DateTime::<Utc>::from_timestamp(replay_expires_at, 0)
        .ok_or(RequestObjectResolutionError::Invalid)?;
    let database = application
        .database()
        .ok_or(RequestObjectResolutionError::Unavailable)?;
    match database
        .register_request_object(
            issuer.url.trim_end_matches('/'),
            &client.id,
            &verified.jti,
            expires_at,
        )
        .await
    {
        Ok(true) => Ok(resolved),
        Ok(false) => {
            tracing::warn!(
                event = "request_object_replay",
                outcome = "rejected",
                client_id = %client.id,
                "authorization request object replay rejected"
            );
            Err(RequestObjectResolutionError::Invalid)
        }
        Err(error) => {
            tracing::error!(%error, "failed to persist request object replay state");
            Err(RequestObjectResolutionError::Unavailable)
        }
    }
}

fn merge_signed_authorization_request(
    outer: &AuthorizationRequest,
    mut signed: AuthorizationRequest,
) -> Option<AuthorizationRequest> {
    let string_matches = |outside: &str, inside: &str| outside.is_empty() || outside == inside;
    let option_matches =
        |outside: &Option<String>, inside: &Option<String>| outside.is_none() || outside == inside;
    let claims_match = |outside: &Option<String>, inside: &Option<String>| {
        outside.is_none()
            || outside == inside
            || outside
                .as_deref()
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .zip(
                    inside
                        .as_deref()
                        .and_then(|value| serde_json::from_str::<Value>(value).ok()),
                )
                .is_some_and(|(outside, inside)| outside == inside)
    };
    let authorization_details_match = |outside: &Option<String>, inside: &Option<String>| {
        outside.is_none()
            || outside == inside
            || outside
                .as_deref()
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .zip(
                    inside
                        .as_deref()
                        .and_then(|value| serde_json::from_str::<Value>(value).ok()),
                )
                .is_some_and(|(outside, inside)| outside == inside)
    };
    if outer.client_id != signed.client_id
        || !string_matches(&outer.response_type, &signed.response_type)
        || !string_matches(&outer.redirect_uri, &signed.redirect_uri)
        || !string_matches(&outer.scope, &signed.scope)
        || !string_matches(&outer.state, &signed.state)
        || !string_matches(&outer.nonce, &signed.nonce)
        || !option_matches(&outer.code_challenge, &signed.code_challenge)
        || !option_matches(&outer.code_challenge_method, &signed.code_challenge_method)
        || !option_matches(&outer.ui_locales, &signed.ui_locales)
        || !option_matches(&outer.prompt, &signed.prompt)
        || !option_matches(&outer.max_age, &signed.max_age)
        || !option_matches(&outer.response_mode, &signed.response_mode)
        || !option_matches(&outer.resource, &signed.resource)
        || !option_matches(&outer.login_hint, &signed.login_hint)
        || !option_matches(&outer.id_token_hint, &signed.id_token_hint)
        || !option_matches(&outer.acr_values, &signed.acr_values)
        || !claims_match(&outer.claims, &signed.claims)
        || !authorization_details_match(&outer.authorization_details, &signed.authorization_details)
        || !option_matches(&outer.dpop_jkt, &signed.dpop_jkt)
    {
        return None;
    }
    signed.request_object = None;
    signed.request_uri = None;
    Some(signed)
}

fn authorization_query_contains_request_uri(query: &str) -> bool {
    url::form_urlencoded::parse(query.as_bytes())
        .any(|(key, value)| key == "request_uri" && value.starts_with(PUSHED_REQUEST_URI_PREFIX))
}

async fn resolve_pushed_authorization(
    issuer_id: &str,
    serialized: &[u8],
    application: &Application,
) -> Result<AuthorizationRequest, AuthorizationInputError> {
    let reference = serde_urlencoded::from_bytes::<AuthorizationReferenceRequest>(serialized)
        .map_err(|_| AuthorizationInputError::Invalid)?;
    if reference.client_id.is_empty()
        || reference.client_id.len() > 256
        || !reference
            .request_uri
            .strip_prefix(PUSHED_REQUEST_URI_PREFIX)
            .is_some_and(valid_opaque_token)
    {
        return Err(AuthorizationInputError::Invalid);
    }
    let snapshot = application.snapshot();
    let issuer = snapshot
        .issuer(issuer_id)
        .ok_or(AuthorizationInputError::Invalid)?;
    if snapshot
        .client_for_issuer(issuer_id, &reference.client_id)
        .is_none()
    {
        return Err(AuthorizationInputError::Invalid);
    }
    let database = application
        .database()
        .ok_or(AuthorizationInputError::Unavailable)?;
    match database
        .consume_pushed_authorization(
            &reference.request_uri,
            issuer.url.trim_end_matches('/'),
            &reference.client_id,
        )
        .await
    {
        Ok(Some(request)) if request.client_id == reference.client_id => Ok(request),
        Ok(_) => Err(AuthorizationInputError::Invalid),
        Err(error) => {
            tracing::error!(%error, "failed to consume pushed authorization request");
            Err(AuthorizationInputError::Unavailable)
        }
    }
}

async fn push_authorization(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<PushedAuthorizationForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.as_str().to_owned();
    let cors_snapshot = application.snapshot();
    let cors_request = request.clone();
    let cors_client_id = form.client_id.clone();
    let mut response = push_authorization_inner(path, request, form, application).await;
    add_token_cors(
        &mut response,
        &cors_request,
        &cors_snapshot,
        &issuer_id,
        Some(cors_client_id.as_str()),
    );
    response
}

async fn push_authorization_inner(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<PushedAuthorizationForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        application.metrics().pushed_authorization(false);
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "unknown issuer");
    };
    let (authorization, client_secret, client_assertion_type, client_assertion) =
        form.into_inner().into_request();
    let client = match authenticated_endpoint_client(
        &snapshot,
        &request,
        application.database(),
        issuer,
        EndpointClientAuthentication {
            form_id: Some(&authorization.client_id),
            form_secret: client_secret.as_deref(),
            client_assertion_type: client_assertion_type.as_deref(),
            client_assertion: client_assertion.as_deref(),
            realm: "par",
            endpoint_path: "/par",
        },
    )
    .await
    {
        Ok(client) => client,
        Err(response) => {
            application.metrics().pushed_authorization(false);
            return response;
        }
    };
    if client.require_signed_request_object && authorization.request_object.is_none() {
        application.metrics().pushed_authorization(false);
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "this client requires a signed authorization request object",
        );
    }
    let Some(database) = application.database() else {
        application.metrics().pushed_authorization(false);
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let dpop = match verified_dpop_endpoint_proof(
        &request,
        database,
        issuer,
        "/par",
        "authorization_server",
        None,
    )
    .await
    {
        Ok(proof) => proof,
        Err(DpopProofError::Invalid) => {
            application.metrics().pushed_authorization(false);
            return invalid_dpop_proof_response("the DPoP proof is invalid or has been replayed");
        }
        Err(DpopProofError::NonceRequired(nonce)) => {
            application.metrics().pushed_authorization(false);
            return dpop_nonce_response(false, &nonce);
        }
        Err(DpopProofError::Unavailable) => {
            application.metrics().pushed_authorization(false);
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "DPoP replay storage unavailable",
            );
        }
    };
    let mut authorization =
        match resolve_authorization_request_object(&issuer_id, authorization, &application).await {
            Ok(authorization) => authorization,
            Err(AuthorizationInputError::Unavailable) => {
                application.metrics().pushed_authorization(false);
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "request object storage unavailable",
                );
            }
            Err(_) => {
                application.metrics().pushed_authorization(false);
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_object",
                    "the signed authorization request is invalid or has already been used",
                );
            }
        };
    if let Err(error) = authorization.validate(&snapshot, &issuer_id) {
        application.metrics().pushed_authorization(false);
        return oauth_error(StatusCode::BAD_REQUEST, error.code, error.description);
    }
    if let Some(proof) = dpop {
        if authorization
            .dpop_jkt
            .as_deref()
            .is_some_and(|thumbprint| thumbprint != proof.jkt)
        {
            application.metrics().pushed_authorization(false);
            return invalid_dpop_proof_response(
                "the DPoP proof does not match the dpop_jkt authorization parameter",
            );
        }
        authorization.dpop_jkt = Some(proof.jkt);
    }
    let rate_limit_keys = [
        format!(
            "par-network:{}",
            authentication_remote_address(&request, forwarded_headers_trusted())
        ),
        format!("par-client:{issuer_id}:{}", client.id),
    ];
    match database
        .allow_authentication_attempts(
            &rate_limit_keys,
            issuer.token_policy.pushed_authorization_request_limit,
            issuer.token_policy.pushed_authorization_request_window,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            application.metrics().pushed_authorization(false);
            application.metrics().request_rate_limit_rejection();
            tracing::warn!(
                event = "pushed_authorization_request",
                outcome = "rate_limited",
                issuer_id,
                client_id = %client.id,
                "pushed authorization request rate limit exceeded"
            );
            let mut response = oauth_error(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "too many pushed authorization requests",
            );
            if let Ok(retry_after) = actix_web::http::header::HeaderValue::from_str(
                &issuer
                    .token_policy
                    .pushed_authorization_request_window
                    .to_string(),
            ) {
                response
                    .headers_mut()
                    .insert(actix_web::http::header::RETRY_AFTER, retry_after);
            }
            return response;
        }
        Err(error) => {
            application.metrics().pushed_authorization(false);
            tracing::error!(%error, "failed to apply pushed authorization request rate limit");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "pushed authorization storage failed",
            );
        }
    }
    let expires_in = issuer.token_policy.pushed_authorization_request_lifetime;
    match database
        .issue_pushed_authorization(
            issuer.url.trim_end_matches('/'),
            &client.id,
            &authorization,
            expires_in,
        )
        .await
    {
        Ok(request_uri) => {
            application.metrics().pushed_authorization(true);
            tracing::info!(
                event = "pushed_authorization_request",
                outcome = "created",
                issuer_id,
                client_id = %client.id,
                "pushed authorization request created"
            );
            no_store_json_response(
                StatusCode::CREATED,
                json!({"request_uri": request_uri, "expires_in": expires_in}),
            )
        }
        Err(error) => {
            application.metrics().pushed_authorization(false);
            tracing::error!(%error, "failed to store pushed authorization request");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "pushed authorization storage failed",
            )
        }
    }
}

async fn authorize_post(
    path: web::Path<String>,
    request: HttpRequest,
    body: web::Bytes,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    if authorization_query_contains_request_uri(std::str::from_utf8(&body).unwrap_or_default()) {
        let authorization = resolve_pushed_authorization(&issuer_id, &body, &application).await;
        return authorization_input_response(&issuer_id, &request, &application, authorization)
            .await;
    }
    let Ok(form) = serde_urlencoded::from_bytes::<AuthorizationPostForm>(&body) else {
        return browser_request_rejection(
            &request,
            "The submitted form is incomplete or malformed",
        );
    };
    let AuthorizationPostForm {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        nonce,
        code_challenge,
        code_challenge_method,
        ui_locales,
        prompt,
        max_age,
        response_mode,
        resource,
        request_object,
        request_uri,
        login_hint,
        id_token_hint,
        acr_values,
        claims,
        authorization_details,
        dpop_jkt,
        transaction,
        csrf_token,
        identifier,
        password,
        mfa_transaction,
        totp_code,
    } = form;
    let protocol_parameters_absent = response_type.is_empty()
        && client_id.is_empty()
        && redirect_uri.is_empty()
        && scope.is_empty()
        && state.is_empty()
        && nonce.is_none()
        && code_challenge.is_none()
        && code_challenge_method.is_none()
        && ui_locales.is_none()
        && prompt.is_none()
        && max_age.is_none()
        && response_mode.is_none()
        && resource.is_none()
        && request_object.is_none()
        && request_uri.is_none()
        && login_hint.is_none()
        && id_token_hint.is_none()
        && acr_values.is_none()
        && claims.is_none()
        && authorization_details.is_none()
        && dpop_jkt.is_none();
    if mfa_transaction.is_some() {
        let (Some(mfa_transaction), Some(csrf_token), Some(totp_code)) =
            (mfa_transaction, csrf_token, totp_code)
        else {
            return browser_request_rejection(
                &request,
                "The submitted verification form is incomplete or malformed",
            );
        };
        if !protocol_parameters_absent
            || transaction.is_some()
            || identifier.is_some()
            || password.is_some()
            || !valid_csrf(&request, &csrf_token)
        {
            return browser_request_rejection(
                &request,
                "The submitted verification form is incomplete or malformed",
            );
        }
        return complete_totp_authentication(
            issuer_id,
            request,
            mfa_transaction,
            csrf_token,
            totp_code,
            application,
        )
        .await;
    }
    if totp_code.is_some() {
        return browser_request_rejection(
            &request,
            "The submitted verification form is incomplete or malformed",
        );
    }
    if let Some(transaction) = transaction {
        let (Some(csrf_token), Some(identifier), Some(password)) =
            (csrf_token, identifier, password)
        else {
            return browser_request_rejection(
                &request,
                "The submitted sign-in form is incomplete or malformed",
            );
        };
        if !protocol_parameters_absent || !valid_csrf(&request, &csrf_token) {
            return browser_request_rejection(
                &request,
                "The submitted sign-in form is incomplete or malformed",
            );
        }
        let snapshot = application.snapshot();
        let Some(issuer) = snapshot.issuer(&issuer_id) else {
            return browser_request_rejection(&request, "The authorization issuer is unknown");
        };
        let Some(database) = application.database() else {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "authorization storage is unavailable",
            );
        };
        let authorization = match database
            .consume_browser_authorization(&transaction, issuer.url.trim_end_matches('/'))
            .await
        {
            Ok(Some(authorization)) => authorization,
            Ok(None) => {
                return protocol_error(
                    &snapshot.configuration.branding,
                    "The sign-in form has expired; please start again",
                    &correlation_id(&request),
                );
            }
            Err(error) => {
                tracing::error!(%error, "failed to consume browser authorization transaction");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "authorization storage failed",
                );
            }
        };
        return complete_authentication(
            issuer_id,
            request,
            authorization,
            csrf_token,
            identifier,
            password,
            application,
        )
        .await;
    }
    let authorization = AuthorizationRequest {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        nonce: nonce.unwrap_or_default(),
        code_challenge,
        code_challenge_method,
        ui_locales,
        prompt,
        max_age,
        response_mode,
        resource,
        request_object,
        request_uri,
        login_hint,
        id_token_hint,
        acr_values,
        claims,
        authorization_details,
        dpop_jkt,
    }
    .normalize_empty_optional_parameters();
    if authorization.request_object.is_none()
        && (authorization.response_type.is_empty()
            || authorization.client_id.is_empty()
            || authorization.redirect_uri.is_empty()
            || authorization.scope.is_empty()
            || authorization.state.is_empty())
    {
        return browser_request_rejection(
            &request,
            "The submitted form is incomplete or malformed",
        );
    }
    let authorization =
        match enforce_signed_request_object_policy(&issuer_id, authorization, &application) {
            Ok(authorization) => authorization,
            Err(error) => {
                return authorization_input_response(
                    &issuer_id,
                    &request,
                    &application,
                    Err(error),
                )
                .await;
            }
        };
    let authorization =
        match resolve_authorization_request_object(&issuer_id, authorization, &application).await {
            Ok(authorization) => authorization,
            Err(error) => {
                return authorization_input_response(
                    &issuer_id,
                    &request,
                    &application,
                    Err(error),
                )
                .await;
            }
        };

    match (csrf_token, identifier, password) {
        (None, None, None) => {
            authorization_input_response(
                &issuer_id,
                &request,
                &application,
                enforce_pushed_authorization_policy(&issuer_id, authorization, &application),
            )
            .await
        }
        _ => browser_request_rejection(&request, "The submitted form is incomplete or malformed"),
    }
}

async fn authorization_response(
    issuer_id: &str,
    request: &HttpRequest,
    application: &Application,
    authorization: Result<AuthorizationRequest, ()>,
) -> HttpResponse {
    let request_id = correlation_id(request);
    let mut session = existing_session(request, application).await;
    let snapshot = application.snapshot();
    let default_branding = &snapshot.configuration.branding;

    let mut response = match authorization {
        Ok(authorization) => match authorization.validate(&snapshot, issuer_id) {
            Ok(client) => {
                let branding = snapshot.branding(Some(issuer_id), Some(&client.id));
                let messages = branding.messages(authorization.ui_locales.as_deref());
                let hinted_subject = match authorization_id_token_hint_subject(
                    application.database(),
                    snapshot.issuer(issuer_id).expect("validated issuer"),
                    client,
                    authorization.id_token_hint.as_deref(),
                )
                .await
                {
                    Ok(subject) => subject,
                    Err(AuthorizationIdTokenHintError::Invalid) => {
                        return authorization_request_error(
                            application.database(),
                            &snapshot,
                            default_branding,
                            issuer_id,
                            &authorization,
                            crate::protocol::AuthorizationError::new(
                                "invalid_request",
                                "The ID token hint is invalid for this client",
                            ),
                            &request_id,
                        )
                        .await;
                    }
                    Err(AuthorizationIdTokenHintError::Unavailable) => {
                        return authorization_request_error(
                            application.database(),
                            &snapshot,
                            default_branding,
                            issuer_id,
                            &authorization,
                            crate::protocol::AuthorizationError::new(
                                "server_error",
                                "The ID token hint could not be verified",
                            ),
                            &request_id,
                        )
                        .await;
                    }
                };
                let session_user = session
                    .subject
                    .as_deref()
                    .and_then(|subject| snapshot.user_for_issuer(issuer_id, subject))
                    .filter(|user| user.totp_secret_reference.is_none() || session.mfa_verified)
                    .filter(|_| {
                        authorization_authentication_context_satisfies(
                            client,
                            &authorization,
                            session.mfa_verified,
                        )
                    });
                if authorization_session_cookie_should_clear(
                    &snapshot,
                    issuer_id,
                    session.subject.as_deref(),
                    session_user.is_some(),
                ) {
                    session.clear_cookie = true;
                }
                let user = match session_user {
                    Some(user) => match crate::pairwise::external_subject(
                        &snapshot,
                        snapshot
                            .issuer(issuer_id)
                            .expect("validated authorization issuer")
                            .url
                            .trim_end_matches('/'),
                        client,
                        &user.id,
                    ) {
                        Ok(subject)
                            if id_token_hint_matches_subject(
                                hinted_subject.as_deref(),
                                &subject,
                            ) =>
                        {
                            Some(user)
                        }
                        Ok(_) => None,
                        Err(_) => {
                            return authorization_request_error(
                                application.database(),
                                &snapshot,
                                default_branding,
                                issuer_id,
                                &authorization,
                                crate::protocol::AuthorizationError::new(
                                    "server_error",
                                    "The subject identifier could not be generated",
                                ),
                                &request_id,
                            )
                            .await;
                        }
                    },
                    None => None,
                };
                let session_auth_time = session
                    .authenticated_at
                    .map(|authenticated_at| authenticated_at.timestamp());
                let session_too_old =
                    authentication_max_age(client, &authorization).is_some_and(|max_age| {
                        max_age == 0
                            || session_auth_time.is_none_or(|auth_time| {
                                auth_time < Utc::now().timestamp().saturating_sub(max_age)
                            })
                    });
                let force_login = authorization.has_prompt("login")
                    || authorization.has_prompt("select_account")
                    || session_too_old;
                let consent_required = authorization_consent_required(client, &authorization);

                if authorization.has_prompt("none") && session.unavailable {
                    authorization_request_error(
                        application.database(),
                        &snapshot,
                        default_branding,
                        issuer_id,
                        &authorization,
                        crate::protocol::AuthorizationError::new(
                            "server_error",
                            "The authenticated session could not be checked",
                        ),
                        &request_id,
                    )
                    .await
                } else if authorization.has_prompt("none") && user.is_none() {
                    authorization_request_error(
                        application.database(),
                        &snapshot,
                        default_branding,
                        issuer_id,
                        &authorization,
                        crate::protocol::AuthorizationError::new(
                            "login_required",
                            "User interaction is required to authenticate",
                        ),
                        &request_id,
                    )
                    .await
                } else if authorization.has_prompt("none") && force_login {
                    authorization_request_error(
                        application.database(),
                        &snapshot,
                        default_branding,
                        issuer_id,
                        &authorization,
                        crate::protocol::AuthorizationError::new(
                            "login_required",
                            "The authenticated session is too old",
                        ),
                        &request_id,
                    )
                    .await
                } else if authorization.has_prompt("none") && consent_required {
                    authorization_request_error(
                        application.database(),
                        &snapshot,
                        default_branding,
                        issuer_id,
                        &authorization,
                        crate::protocol::AuthorizationError::new(
                            "consent_required",
                            "User interaction is required to grant consent",
                        ),
                        &request_id,
                    )
                    .await
                } else if let Some(user) = user.filter(|_| !force_login) {
                    resume_authorization(
                        application,
                        &snapshot,
                        issuer_id,
                        &authorization,
                        client,
                        user,
                        session_auth_time.unwrap_or_else(|| Utc::now().timestamp()),
                        session.mfa_verified,
                        session.session_id.as_deref(),
                        &branding,
                        &messages,
                        request,
                    )
                    .await
                } else {
                    render_login(
                        application,
                        &snapshot,
                        issuer_id,
                        &authorization,
                        client,
                        &branding,
                        &messages,
                        request,
                    )
                    .await
                }
            }
            Err(error) => {
                authorization_request_error(
                    application.database(),
                    &snapshot,
                    default_branding,
                    issuer_id,
                    &authorization,
                    error,
                    &request_id,
                )
                .await
            }
        },
        Err(_) => protocol_error(
            default_branding,
            "The authorization request is incomplete or malformed",
            &request_id,
        ),
    };
    if session.clear_cookie {
        remove_session_cookie(&mut response, request);
    }
    response
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationIdTokenHintError {
    Invalid,
    Unavailable,
}

async fn authorization_id_token_hint_subject(
    database: Option<&Database>,
    issuer: &crate::configuration::Issuer,
    client: &crate::configuration::Client,
    hint: Option<&str>,
) -> Result<Option<String>, AuthorizationIdTokenHintError> {
    let Some(hint) = hint else {
        return Ok(None);
    };
    let database = database.ok_or(AuthorizationIdTokenHintError::Unavailable)?;
    let issuer_url = issuer.url.trim_end_matches('/');
    let keys = database
        .verification_signing_keys(issuer_url)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to load signing keys for authorization ID token hint");
            AuthorizationIdTokenHintError::Unavailable
        })?;
    keys.iter()
        .find_map(|key| {
            tokens::verify_id_token_hint(hint, key, issuer_url, &client.id)
                .ok()
                .map(|claims| claims.sub)
        })
        .map(Some)
        .ok_or(AuthorizationIdTokenHintError::Invalid)
}

fn id_token_hint_matches_subject(
    hinted_subject: Option<&str>,
    authenticated_subject: &str,
) -> bool {
    hinted_subject.is_none_or(|subject| subject == authenticated_subject)
}

#[allow(clippy::too_many_arguments)]
async fn render_login(
    application: &Application,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    authorization: &AuthorizationRequest,
    client: &crate::configuration::Client,
    branding: &crate::configuration::Branding,
    messages: &crate::configuration::UiMessages,
    request: &HttpRequest,
) -> HttpResponse {
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "authorization storage is unavailable",
        );
    };
    let Some(issuer) = snapshot.issuer(issuer_id) else {
        return protocol_error(
            &snapshot.configuration.branding,
            "The authorization issuer is unknown",
            &correlation_id(request),
        );
    };
    let transaction = match database
        .issue_browser_authorization(
            issuer.url.trim_end_matches('/'),
            authorization,
            issuer.token_policy.browser_authorization_lifetime,
        )
        .await
    {
        Ok(transaction) => transaction,
        Err(error) => {
            tracing::error!(%error, "failed to persist browser authorization transaction");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "authorization storage failed",
            );
        }
    };
    let csrf_token = random_token();
    let mut response = html_response(
        StatusCode::OK,
        LoginTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id,
            client_name: if client.name.is_empty() {
                &client.id
            } else {
                &client.name
            },
            transaction: &transaction,
            csrf_token: &csrf_token,
            identifier: authorization.login_hint.as_deref().unwrap_or_default(),
            has_error: false,
            error: None,
            messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
            support_url: branding.support_url.as_deref(),
            privacy_url: branding.privacy_url.as_deref(),
            terms_url: branding.terms_url.as_deref(),
        }
        .render(),
    );
    add_csrf_cookie(&mut response, request, &csrf_token);
    response
}

#[allow(clippy::too_many_arguments)]
async fn resume_authorization(
    application: &Application,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    authorization: &AuthorizationRequest,
    client: &crate::configuration::Client,
    user: &crate::configuration::User,
    auth_time: i64,
    mfa_verified: bool,
    session_id: Option<&str>,
    branding: &crate::configuration::Branding,
    messages: &crate::configuration::UiMessages,
    request: &HttpRequest,
) -> HttpResponse {
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    if !essential_claims_satisfied(
        snapshot,
        issuer_id,
        authorization,
        user,
        auth_time,
        mfa_verified,
    ) {
        return authorization_request_error(
            Some(database),
            snapshot,
            &snapshot.configuration.branding,
            issuer_id,
            authorization,
            crate::protocol::AuthorizationError::new(
                "access_denied",
                "An essential requested claim cannot be satisfied",
            ),
            &correlation_id(request),
        )
        .await;
    }
    let grant = build_authorization_grant(
        snapshot,
        issuer_id,
        authorization,
        user,
        auth_time,
        mfa_verified,
        session_id,
    );
    tracing::info!(
        event = "authentication_session",
        outcome = "reused",
        issuer_id,
        client_id = %grant.client_id,
        subject_id = %grant.subject,
        "authenticated browser session reused"
    );

    if authorization_consent_required(client, authorization) {
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
        let csrf_token = random_token();
        let scopes = consent_scopes(&grant.scopes, messages);
        let authorization_details =
            consent_authorization_details(snapshot, &grant.authorization_details);
        let mut response = html_response(
            StatusCode::OK,
            ConsentTemplate {
                product_name: &branding.product_name,
                primary_color: &branding.primary_color,
                issuer_id,
                client_name: if client.name.is_empty() {
                    &client.id
                } else {
                    &client.name
                },
                scopes: &scopes,
                authorization_details: &authorization_details,
                transaction: &transaction,
                csrf_token: &csrf_token,
                messages,
                logo: branding.logo.as_deref(),
                favicon: branding.favicon.as_deref(),
                font_family: branding.font_family.as_deref(),
                support_url: branding.support_url.as_deref(),
                privacy_url: branding.privacy_url.as_deref(),
                terms_url: branding.terms_url.as_deref(),
            }
            .render(),
        );
        add_csrf_cookie(&mut response, request, &csrf_token);
        response
    } else {
        match authorization_success(
            database,
            &grant,
            &authorization.state,
            branding,
            request,
            snapshot
                .configuration
                .authentication
                .session
                .absolute_timeout,
        )
        .await
        {
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
}

fn build_authorization_grant(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    authorization: &AuthorizationRequest,
    user: &crate::configuration::User,
    auth_time: i64,
    mfa_verified: bool,
    session_id: Option<&str>,
) -> AuthorizationGrant {
    let issuer = snapshot.issuer(issuer_id).expect("validated issuer");
    let scopes = normalized_scopes(&authorization.scope);
    let claims = tokens::mapped_claims(snapshot, user, &scopes);
    let client = snapshot
        .client_for_issuer(issuer_id, &authorization.client_id)
        .expect("validated authorization client");
    let authorization_details = authorization
        .authorization_details_value(snapshot, client)
        .expect("validated authorization details");
    AuthorizationGrant {
        issuer: issuer.url.trim_end_matches('/').to_owned(),
        subject: user.id.clone(),
        client_id: authorization.client_id.clone(),
        redirect_uri: authorization.redirect_uri.clone(),
        scopes,
        nonce: (!authorization.nonce.is_empty()).then(|| authorization.nonce.clone()),
        code_challenge: authorization.code_challenge.clone(),
        response_mode: authorization.response_mode.clone(),
        resource: authorization.resource.clone(),
        dpop_jkt: authorization.dpop_jkt.clone(),
        session_id: session_id.map(str::to_owned),
        auth_time: Some(auth_time),
        mfa_verified,
        claims: json!(claims),
        authorization_details,
        expires_at: Utc::now() + Duration::seconds(issuer.token_policy.authorization_code_lifetime),
    }
}

async fn complete_authentication(
    issuer_id: String,
    request: HttpRequest,
    authorization: AuthorizationRequest,
    csrf_token: String,
    submitted_identifier: String,
    password: String,
    application: web::Data<Application>,
) -> HttpResponse {
    let request_id = correlation_id(&request);
    let snapshot = application.snapshot();
    let default_branding = &snapshot.configuration.branding;

    if !valid_csrf(&request, &csrf_token) {
        return protocol_error(
            default_branding,
            "The sign-in form has expired; please start again",
            &request_id,
        );
    }

    let client = match authorization.validate(&snapshot, &issuer_id) {
        Ok(client) => client,
        Err(error) => return protocol_error(default_branding, error.description, &request_id),
    };
    let issuer = snapshot
        .issuer(&issuer_id)
        .expect("the authorization request validated its issuer");
    let branding = snapshot.branding(Some(&issuer_id), Some(&client.id));
    let messages = branding.messages(authorization.ui_locales.as_deref());
    let Some(database) = application.database() else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "database_unavailable"}),
        );
    };
    let submitted_identifier = submitted_identifier.trim();
    let identifier_allowed = valid_submitted_identifier(submitted_identifier);
    let password_allowed = valid_submitted_password(&password);
    let credentials_shape_valid = identifier_allowed && password_allowed;
    let identifier = if identifier_allowed {
        submitted_identifier.to_owned()
    } else {
        String::new()
    };
    let remote_address = authentication_remote_address(&request, forwarded_headers_trusted());
    let rate_limit_keys = authentication_rate_limit_keys(
        &issuer_id,
        &remote_address,
        identifier_allowed.then_some(identifier.as_str()),
    );
    let rate_limit = &snapshot.configuration.authentication.rate_limit;
    match database
        .allow_authentication_attempts(
            &rate_limit_keys,
            rate_limit.attempts,
            rate_limit.window_seconds,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            application.metrics().rate_limit_rejection();
            tracing::warn!(
                event = "authentication_rate_limit",
                outcome = "rejected",
                issuer_id,
                client_id = %authorization.client_id
            );
            let transaction = match database
                .issue_browser_authorization(
                    issuer.url.trim_end_matches('/'),
                    &authorization,
                    issuer.token_policy.browser_authorization_lifetime,
                )
                .await
            {
                Ok(transaction) => transaction,
                Err(error) => {
                    tracing::error!(%error, "failed to renew browser authorization transaction");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "authorization storage failed",
                    );
                }
            };
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
                    transaction: &transaction,
                    csrf_token: &csrf_token,
                    identifier: &identifier,
                    has_error: true,
                    error: Some(&messages.sign_in_rate_limited),
                    messages: &messages,
                    logo: branding.logo.as_deref(),
                    favicon: branding.favicon.as_deref(),
                    font_family: branding.font_family.as_deref(),
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
    let user = credentials_shape_valid
        .then(|| {
            snapshot
                .user_by_identifier_for_issuer(&issuer_id, &identifier)
                .cloned()
        })
        .flatten();
    let hash = user
        .as_ref()
        .map(|user| user.password_hash.clone())
        .unwrap_or_else(|| snapshot.dummy_password_hash().to_owned());
    let password = if credentials_shape_valid {
        password
    } else {
        "invalid-credential-shape".to_owned()
    };
    let password_verified = web::block(move || bcrypt::verify(password, &hash).unwrap_or(false))
        .await
        .unwrap_or(false);
    let valid_password = credentials_shape_valid && password_verified;

    let Some(user) = user.filter(|_| valid_password) else {
        application.metrics().authentication(false);
        tracing::warn!(
            event = "authentication",
            outcome = "failure",
            issuer_id,
            client_id = %authorization.client_id,
            reason = "invalid_credentials"
        );
        let transaction = match database
            .issue_browser_authorization(
                issuer.url.trim_end_matches('/'),
                &authorization,
                issuer.token_policy.browser_authorization_lifetime,
            )
            .await
        {
            Ok(transaction) => transaction,
            Err(error) => {
                tracing::error!(%error, "failed to renew browser authorization transaction");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "authorization storage failed",
                );
            }
        };
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
                transaction: &transaction,
                csrf_token: &csrf_token,
                identifier: &identifier,
                has_error: true,
                error: Some(&messages.sign_in_invalid_credentials),
                messages: &messages,
                logo: branding.logo.as_deref(),
                favicon: branding.favicon.as_deref(),
                font_family: branding.font_family.as_deref(),
                support_url: branding.support_url.as_deref(),
                privacy_url: branding.privacy_url.as_deref(),
                terms_url: branding.terms_url.as_deref(),
            }
            .render(),
        );
    };
    if authorization_requires_mfa(client, &authorization) && user.totp_secret_reference.is_none() {
        application.metrics().authentication(false);
        application.metrics().mfa(MfaOutcome::Rejected);
        tracing::warn!(
            event = "authentication",
            outcome = "failure",
            issuer_id,
            client_id = %authorization.client_id,
            reason = "required_mfa_unavailable"
        );
        return authorization_request_error(
            Some(database),
            &snapshot,
            default_branding,
            &issuer_id,
            &authorization,
            crate::protocol::AuthorizationError::new(
                "access_denied",
                "The application requires multi-factor authentication",
            ),
            &request_id,
        )
        .await;
    }
    if let Some(reference) = &user.totp_secret_reference {
        if !authorization_authentication_context_satisfies(client, &authorization, true) {
            application.metrics().authentication(false);
            application.metrics().mfa(MfaOutcome::Rejected);
            return authorization_request_error(
                Some(database),
                &snapshot,
                default_branding,
                &issuer_id,
                &authorization,
                crate::protocol::AuthorizationError::new(
                    "access_denied",
                    "The requested authentication context cannot be satisfied",
                ),
                &request_id,
            )
            .await;
        }
        if let Err(error) = crate::totp::secret_from_reference(reference) {
            tracing::error!(?error, "configured TOTP secret is unavailable");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "multi-factor authentication is unavailable",
            );
        }
        let payload = serde_json::to_value(&authorization)
            .expect("validated authorization request serializes");
        let transaction = match database
            .issue_totp_challenge(
                issuer.url.trim_end_matches('/'),
                &user.id,
                "authorization",
                &payload,
                issuer.token_policy.browser_authorization_lifetime,
            )
            .await
        {
            Ok(transaction) => transaction,
            Err(error) => {
                tracing::error!(%error, "failed to persist TOTP challenge");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "multi-factor authentication storage failed",
                );
            }
        };
        application.metrics().mfa(MfaOutcome::Challenged);
        return render_totp_challenge(
            &request,
            &snapshot,
            &issuer_id,
            client,
            &authorization,
            &transaction,
            &csrf_token,
            None,
            StatusCode::OK,
        );
    }

    finish_authenticated_authorization(
        &request,
        &application,
        &snapshot,
        &issuer_id,
        &authorization,
        client,
        &user,
        &csrf_token,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn render_totp_challenge(
    request: &HttpRequest,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    client: &crate::configuration::Client,
    authorization: &AuthorizationRequest,
    transaction: &str,
    csrf_token: &str,
    error: Option<&str>,
    status: StatusCode,
) -> HttpResponse {
    let branding = snapshot.branding(Some(issuer_id), Some(&client.id));
    let messages = branding.messages(authorization.ui_locales.as_deref());
    let form_action = format!("/{issuer_id}/authorize");
    let mut response = html_response(
        status,
        TotpTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            client_name: if client.name.is_empty() {
                &client.id
            } else {
                &client.name
            },
            transaction,
            form_action: &form_action,
            transaction_field: "mfa_transaction",
            action_value: None,
            csrf_token,
            has_error: error.is_some(),
            error,
            messages: &messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
            support_url: branding.support_url.as_deref(),
            privacy_url: branding.privacy_url.as_deref(),
            terms_url: branding.terms_url.as_deref(),
        }
        .render(),
    );
    add_csrf_cookie(&mut response, request, csrf_token);
    response
}

async fn complete_totp_authentication(
    issuer_id: String,
    request: HttpRequest,
    transaction: String,
    csrf_token: String,
    submitted_code: String,
    application: web::Data<Application>,
) -> HttpResponse {
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return browser_request_rejection(&request, "The authorization issuer is unknown");
    };
    let issuer_url = issuer.url.trim_end_matches('/');
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "authorization storage is unavailable",
        );
    };
    let challenge = match database
        .totp_challenge(&transaction, issuer_url, "authorization")
        .await
    {
        Ok(Some(challenge)) => challenge,
        Ok(None) => {
            let message = snapshot
                .branding(Some(&issuer_id), None)
                .messages(None)
                .totp_expired;
            return protocol_error(
                &snapshot.configuration.branding,
                &message,
                &correlation_id(&request),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load TOTP challenge");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "multi-factor authentication storage failed",
            );
        }
    };
    let authorization = match serde_json::from_value::<AuthorizationRequest>(challenge.payload) {
        Ok(authorization) => authorization,
        Err(error) => {
            tracing::error!(%error, "stored TOTP authorization challenge is invalid");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "multi-factor authentication storage failed",
            );
        }
    };
    let client = match authorization.validate(&snapshot, &issuer_id) {
        Ok(client) => client,
        Err(error) => {
            return protocol_error(
                &snapshot.configuration.branding,
                error.description,
                &correlation_id(&request),
            );
        }
    };
    let Some(user) = snapshot.user_for_issuer(&issuer_id, &challenge.subject) else {
        return protocol_error(
            &snapshot.configuration.branding,
            "This verification is no longer valid",
            &correlation_id(&request),
        );
    };
    let Some(reference) = user.totp_secret_reference.as_ref() else {
        return protocol_error(
            &snapshot.configuration.branding,
            "This verification is no longer valid",
            &correlation_id(&request),
        );
    };
    let branding = snapshot.branding(Some(&issuer_id), Some(&client.id));
    let messages = branding.messages(authorization.ui_locales.as_deref());
    let remote_address = authentication_remote_address(&request, forwarded_headers_trusted());
    let rate_limit_keys =
        authentication_rate_limit_keys(&issuer_id, &remote_address, Some(&user.identifier));
    let rate_limit = &snapshot.configuration.authentication.rate_limit;
    match database
        .allow_authentication_attempts(
            &rate_limit_keys,
            rate_limit.attempts,
            rate_limit.window_seconds,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            application.metrics().rate_limit_rejection();
            let mut response = render_totp_challenge(
                &request,
                &snapshot,
                &issuer_id,
                client,
                &authorization,
                &transaction,
                &csrf_token,
                Some(&messages.sign_in_rate_limited),
                StatusCode::TOO_MANY_REQUESTS,
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
            tracing::error!(%error, "failed to rate-limit TOTP authentication");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "authentication storage failed",
            );
        }
    }
    let secret = match crate::totp::secret_from_reference(reference) {
        Ok(secret) => secret,
        Err(error) => {
            tracing::error!(?error, "configured TOTP secret is unavailable");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "multi-factor authentication is unavailable",
            );
        }
    };
    let Some(counter) = crate::totp::verify(&secret, &submitted_code, Utc::now().timestamp())
    else {
        application.metrics().authentication(false);
        application.metrics().mfa(MfaOutcome::Failure);
        tracing::warn!(
            event = "authentication",
            outcome = "failure",
            issuer_id,
            client_id = %client.id,
            reason = "invalid_totp"
        );
        return render_totp_challenge(
            &request,
            &snapshot,
            &issuer_id,
            client,
            &authorization,
            &transaction,
            &csrf_token,
            Some(&messages.totp_invalid_code),
            StatusCode::UNPROCESSABLE_ENTITY,
        );
    };
    match database
        .consume_totp_challenge(&transaction, issuer_url, &user.id, "authorization", counter)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            application.metrics().authentication(false);
            application.metrics().mfa(MfaOutcome::Rejected);
            let message = snapshot
                .branding(Some(&issuer_id), Some(&client.id))
                .messages(authorization.ui_locales.as_deref())
                .totp_expired;
            return protocol_error(
                &snapshot.configuration.branding,
                &message,
                &correlation_id(&request),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to consume TOTP challenge");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "multi-factor authentication storage failed",
            );
        }
    }
    application.metrics().mfa(MfaOutcome::Success);
    finish_authenticated_authorization(
        &request,
        &application,
        &snapshot,
        &issuer_id,
        &authorization,
        client,
        user,
        &csrf_token,
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn finish_authenticated_authorization(
    request: &HttpRequest,
    application: &Application,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    authorization: &AuthorizationRequest,
    client: &crate::configuration::Client,
    user: &crate::configuration::User,
    csrf_token: &str,
    mfa_verified: bool,
) -> HttpResponse {
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "authorization storage is unavailable",
        );
    };
    let issuer = snapshot
        .issuer(issuer_id)
        .expect("the authorization request validated its issuer");
    let hinted_subject = match authorization_id_token_hint_subject(
        Some(database),
        issuer,
        client,
        authorization.id_token_hint.as_deref(),
    )
    .await
    {
        Ok(subject) => subject,
        Err(AuthorizationIdTokenHintError::Invalid) => {
            return authorization_request_error(
                Some(database),
                snapshot,
                &snapshot.configuration.branding,
                issuer_id,
                authorization,
                crate::protocol::AuthorizationError::new(
                    "invalid_request",
                    "The ID token hint is invalid for this client",
                ),
                &correlation_id(request),
            )
            .await;
        }
        Err(AuthorizationIdTokenHintError::Unavailable) => {
            return authorization_request_error(
                Some(database),
                snapshot,
                &snapshot.configuration.branding,
                issuer_id,
                authorization,
                crate::protocol::AuthorizationError::new(
                    "server_error",
                    "The ID token hint could not be verified",
                ),
                &correlation_id(request),
            )
            .await;
        }
    };
    let external_subject = match crate::pairwise::external_subject(
        snapshot,
        issuer.url.trim_end_matches('/'),
        client,
        &user.id,
    ) {
        Ok(subject) => subject,
        Err(_) => {
            return authorization_request_error(
                Some(database),
                snapshot,
                &snapshot.configuration.branding,
                issuer_id,
                authorization,
                crate::protocol::AuthorizationError::new(
                    "server_error",
                    "The subject identifier could not be generated",
                ),
                &correlation_id(request),
            )
            .await;
        }
    };
    if !id_token_hint_matches_subject(hinted_subject.as_deref(), &external_subject) {
        application.metrics().authentication(false);
        return authorization_request_error(
            Some(database),
            snapshot,
            &snapshot.configuration.branding,
            issuer_id,
            authorization,
            crate::protocol::AuthorizationError::new(
                "login_required",
                "The authenticated user does not match the ID token hint",
            ),
            &correlation_id(request),
        )
        .await;
    }
    let auth_time = Utc::now().timestamp();
    if !authorization_authentication_context_satisfies(client, authorization, mfa_verified)
        || !essential_claims_satisfied(
            snapshot,
            issuer_id,
            authorization,
            user,
            auth_time,
            mfa_verified,
        )
    {
        application.metrics().authentication(false);
        return authorization_request_error(
            Some(database),
            snapshot,
            &snapshot.configuration.branding,
            issuer_id,
            authorization,
            crate::protocol::AuthorizationError::new(
                "access_denied",
                "An essential requested claim cannot be satisfied",
            ),
            &correlation_id(request),
        )
        .await;
    }
    let branding = snapshot.branding(Some(issuer_id), Some(&client.id));
    let messages = branding.messages(authorization.ui_locales.as_deref());
    let mut grant = build_authorization_grant(
        snapshot,
        issuer_id,
        authorization,
        user,
        auth_time,
        mfa_verified,
        None,
    );
    let session_policy = &snapshot.configuration.authentication.session;
    let session = match database
        .start_session_details(
            &grant.subject,
            session_policy.max_concurrent.max(1),
            session_policy.absolute_timeout.max(1),
            mfa_verified,
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
    grant.session_id = Some(session.session_id.clone());
    tracing::info!(
        event = "authentication",
        outcome = "success",
        issuer_id,
        client_id = %grant.client_id,
        subject_id = %grant.subject,
        mfa_verified
    );
    application.metrics().authentication(true);

    if authorization_consent_required(client, authorization) {
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
        let scopes = consent_scopes(&grant.scopes, &messages);
        let authorization_details =
            consent_authorization_details(snapshot, &grant.authorization_details);
        let mut response = html_response(
            StatusCode::OK,
            ConsentTemplate {
                product_name: &branding.product_name,
                primary_color: &branding.primary_color,
                issuer_id,
                client_name: if client.name.is_empty() {
                    &client.id
                } else {
                    &client.name
                },
                scopes: &scopes,
                authorization_details: &authorization_details,
                transaction: &transaction,
                csrf_token,
                messages: &messages,
                logo: branding.logo.as_deref(),
                favicon: branding.favicon.as_deref(),
                font_family: branding.font_family.as_deref(),
                support_url: branding.support_url.as_deref(),
                privacy_url: branding.privacy_url.as_deref(),
                terms_url: branding.terms_url.as_deref(),
            }
            .render(),
        );
        add_session_cookie(
            &mut response,
            request,
            &session.token,
            &session.session_id,
            session_policy.absolute_timeout,
        );
        return response;
    }

    match authorization_success(
        database,
        &grant,
        &authorization.state,
        &branding,
        request,
        session_policy.absolute_timeout,
    )
    .await
    {
        Ok(mut response) => {
            add_session_cookie(
                &mut response,
                request,
                &session.token,
                &session.session_id,
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
    let request_id = correlation_id(&request);
    let snapshot = application.snapshot();
    let form = form.into_inner();
    let branding = &snapshot.configuration.branding;
    if !valid_csrf(&request, &form.csrf_token) {
        return protocol_error(
            branding,
            "The consent form has expired; please start again",
            &request_id,
        );
    }
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let Some(session) = session_token(&request) else {
        let mut response = protocol_error(
            branding,
            "Your sign-in session has expired; please start again",
            &request_id,
        );
        remove_session_cookie(&mut response, &request);
        return response;
    };
    let session_policy = &snapshot.configuration.authentication.session;
    let subject = match database
        .validate_session(&session, session_policy.idle_timeout.max(1))
        .await
    {
        Ok(Some(subject)) => subject,
        Ok(None) => {
            let mut response = protocol_error(
                branding,
                "Your sign-in session has expired; please start again",
                &request_id,
            );
            remove_session_cookie(&mut response, &request);
            return response;
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
        Ok(_) => {
            return protocol_error(
                branding,
                "This authorization request has expired",
                &request_id,
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to consume pending authorization");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "authorization storage failed",
            );
        }
    };
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return protocol_error(branding, "The authorization issuer is unknown", &request_id);
    };
    if pending.issuer != issuer.url.trim_end_matches('/') || pending.subject != subject {
        return protocol_error(
            branding,
            "This authorization request is not valid",
            &request_id,
        );
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
            match authorization_success(
                database,
                &grant,
                &state,
                branding,
                &request,
                session_policy.absolute_timeout,
            )
            .await
            {
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
            authorization_denied(
                database,
                &pending,
                branding,
                &request,
                session_policy.absolute_timeout,
            )
            .await
        }
        _ => protocol_error(branding, "The consent decision is invalid", &request_id),
    }
}

async fn logout_confirmation(
    path: web::Path<String>,
    request: HttpRequest,
    query: web::Query<LogoutRequest>,
    application: web::Data<Application>,
) -> HttpResponse {
    logout_confirmation_response(
        path.into_inner(),
        &request,
        query.into_inner(),
        &application,
    )
    .await
}

async fn logout_confirmation_response(
    issuer_id: String,
    request: &HttpRequest,
    mut query: LogoutRequest,
    application: &Application,
) -> HttpResponse {
    let request_id = correlation_id(request);
    for parameter in [
        &mut query.id_token_hint,
        &mut query.logout_hint,
        &mut query.client_id,
        &mut query.post_logout_redirect_uri,
        &mut query.state,
        &mut query.ui_locales,
    ] {
        if parameter.as_deref() == Some("") {
            *parameter = None;
        }
    }
    let snapshot = application.snapshot();
    let default_branding = &snapshot.configuration.branding;
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return protocol_error(
            default_branding,
            "The logout issuer is unknown",
            &request_id,
        );
    };
    let issuer_branding = snapshot.branding(Some(&issuer_id), None);
    if query
        .id_token_hint
        .as_deref()
        .is_some_and(|value| value.len() > MAX_LOGOUT_HINT_BYTES)
        || query
            .logout_hint
            .as_deref()
            .is_some_and(|value| value.len() > 2_048)
        || query
            .client_id
            .as_deref()
            .is_some_and(|value| value.len() > 256)
        || query
            .post_logout_redirect_uri
            .as_deref()
            .is_some_and(|value| value.len() > 4_096)
        || query
            .state
            .as_deref()
            .is_some_and(|value| value.len() > 1_024)
        || query
            .ui_locales
            .as_deref()
            .is_some_and(|value| value.len() > 256)
    {
        return protocol_error(
            &issuer_branding,
            "One or more logout parameters exceed the supported length",
            &request_id,
        );
    }
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let clear_session = invalid_existing_session(request, application).await;

    let hint_claims = if let Some(hint) = query.id_token_hint.as_deref() {
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
            tokens::verify_logout_id_token_hint(hint, key, issuer.url.trim_end_matches('/')).ok()
        });
        let Some(claims) = claims else {
            return protocol_error(
                &issuer_branding,
                "The ID token hint is invalid",
                &request_id,
            );
        };
        Some(claims)
    } else {
        None
    };

    let client = match resolve_logout_client(
        &snapshot,
        &issuer_id,
        query.client_id.as_deref(),
        hint_claims.as_ref().map(|claims| claims.aud.as_str()),
    ) {
        Ok(client) => client,
        Err(LogoutClientError::UnknownClient) => {
            return protocol_error(
                &issuer_branding,
                "The logout client is unknown",
                &request_id,
            );
        }
        Err(LogoutClientError::ClientMismatch) => {
            return protocol_error(
                &issuer_branding,
                "The logout client does not match the ID token audience",
                &request_id,
            );
        }
        Err(LogoutClientError::UnknownAudience) => {
            return protocol_error(
                &issuer_branding,
                "The ID token audience is unknown",
                &request_id,
            );
        }
    };
    let branding = snapshot.branding(Some(&issuer_id), client.map(|client| client.id.as_str()));

    let return_to = match query.post_logout_redirect_uri.as_deref() {
        Some(uri) => {
            let Some(client) = client else {
                return protocol_error(
                    &branding,
                    "A client_id or ID token hint is required for a post-logout redirect",
                    &request_id,
                );
            };
            if !client
                .post_logout_redirect_uris
                .iter()
                .any(|registered| registered == uri)
            {
                return protocol_error(
                    &branding,
                    "The post-logout redirect URI is not registered",
                    &request_id,
                );
            }
            match redirect_with_state(uri, query.state.as_deref()) {
                Some(uri) => Some(uri),
                None => {
                    return protocol_error(
                        &branding,
                        "The post-logout redirect URI is invalid",
                        &request_id,
                    );
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
    let messages = branding.messages(query.ui_locales.as_deref());
    let mut response = html_response(
        StatusCode::OK,
        LogoutTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id: &issuer_id,
            transaction: &transaction,
            csrf_token: &csrf_token,
            messages: &messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
        }
        .render(),
    );
    add_csrf_cookie(&mut response, request, &csrf_token);
    if clear_session {
        remove_session_cookie(&mut response, request);
    }
    response
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogoutClientError {
    UnknownClient,
    ClientMismatch,
    UnknownAudience,
}

fn resolve_logout_client<'a>(
    snapshot: &'a crate::configuration::Snapshot,
    issuer_id: &str,
    client_id: Option<&str>,
    hint_audience: Option<&str>,
) -> Result<Option<&'a crate::configuration::Client>, LogoutClientError> {
    if let Some(client_id) = client_id {
        let client = snapshot
            .client_for_issuer(issuer_id, client_id)
            .ok_or(LogoutClientError::UnknownClient)?;
        if hint_audience.is_some_and(|audience| audience != client.id) {
            return Err(LogoutClientError::ClientMismatch);
        }
        return Ok(Some(client));
    }
    if let Some(audience) = hint_audience {
        return snapshot
            .client_for_issuer(issuer_id, audience)
            .map(Some)
            .ok_or(LogoutClientError::UnknownAudience);
    }
    Ok(None)
}

async fn logout(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<LogoutPostForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let form = form.into_inner();
    match (form.transaction, form.csrf_token) {
        (None, None) => {
            logout_confirmation_response(issuer_id, &request, form.request, &application).await
        }
        (Some(transaction), Some(csrf_token)) if form.request.parameters_absent() => {
            complete_logout(issuer_id, &request, transaction, csrf_token, &application).await
        }
        _ => browser_request_rejection(
            &request,
            "The submitted logout form is incomplete or malformed",
        ),
    }
}

async fn complete_logout(
    issuer_id: String,
    request: &HttpRequest,
    transaction: String,
    csrf_token: String,
    application: &Application,
) -> HttpResponse {
    let request_id = correlation_id(request);
    let branding = application.snapshot().branding(Some(&issuer_id), None);
    if !valid_csrf(request, &csrf_token) {
        return protocol_error(
            &branding,
            "The logout form has expired; please start again",
            &request_id,
        );
    }
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let return_to = match database.consume_logout_transaction(&transaction).await {
        Ok(Some(return_to)) => return_to,
        Ok(None) => {
            return protocol_error(&branding, "This logout request has expired", &request_id);
        }
        Err(error) => {
            tracing::error!(%error, "failed to consume logout transaction");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "logout storage failed",
            );
        }
    };

    let session = session_token(request);
    let session_present = session.is_some();
    let logout_targets = if let Some(session) = session {
        match database.revoke_session_and_clients(&session).await {
            Ok(targets) => targets,
            Err(error) => {
                tracing::error!(%error, "failed to revoke session during logout");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "session storage failed",
                );
            }
        }
    } else {
        Vec::new()
    };
    let frontchannel_uris = frontchannel_logout_uris(&application.snapshot(), &logout_targets);
    dispatch_backchannel_logout(application, logout_targets).await;

    let messages = branding.messages(None);
    let mut response = if frontchannel_uris.is_empty() {
        match return_to {
            Some(uri) => redirect_response(uri),
            None => html_response(
                StatusCode::OK,
                LogoutDoneTemplate {
                    product_name: &branding.product_name,
                    primary_color: &branding.primary_color,
                    messages: &messages,
                    logo: branding.logo.as_deref(),
                    favicon: branding.favicon.as_deref(),
                    font_family: branding.font_family.as_deref(),
                }
                .render(),
            ),
        }
    } else {
        let destination = return_to.as_deref().unwrap_or("/");
        let mut response = html_response(
            StatusCode::OK,
            FrontchannelLogoutTemplate {
                product_name: &branding.product_name,
                primary_color: &branding.primary_color,
                destination,
                logout_uris: &frontchannel_uris,
                messages: &messages,
                logo: branding.logo.as_deref(),
                favicon: branding.favicon.as_deref(),
                font_family: branding.font_family.as_deref(),
            }
            .render(),
        );
        prevent_caching(&mut response);
        set_frontchannel_content_security_policy(&mut response, &frontchannel_uris);
        response
    };
    remove_session_cookie(&mut response, request);
    tracing::info!(
        event = "logout",
        outcome = "success",
        issuer_id,
        session_present,
        "browser session ended"
    );
    response
}

fn frontchannel_logout_uris(
    snapshot: &crate::configuration::Snapshot,
    targets: &[crate::database::LogoutTarget],
) -> Vec<String> {
    let mut uris = targets
        .iter()
        .filter_map(|target| {
            let client = snapshot.client_for_issuer_url(&target.issuer, &target.client_id)?;
            let configured = client.frontchannel_logout_uri.as_deref()?;
            let mut uri = url::Url::parse(configured).ok()?;
            if client.frontchannel_logout_session_required {
                uri.query_pairs_mut()
                    .append_pair("iss", &target.issuer)
                    .append_pair("sid", &target.session_id);
            }
            Some(uri.to_string())
        })
        .collect::<Vec<_>>();
    uris.sort();
    uris.dedup();
    uris
}

fn set_frontchannel_content_security_policy(response: &mut HttpResponse, uris: &[String]) {
    let mut origins = uris
        .iter()
        .filter_map(|uri| url::Url::parse(uri).ok())
        .map(|uri| uri.origin().ascii_serialization())
        .collect::<Vec<_>>();
    origins.sort();
    origins.dedup();
    let content_security_policy = format!(
        "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data: https:; frame-src {}; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        origins.join(" ")
    );
    let value = actix_web::http::header::HeaderValue::from_str(&content_security_policy)
        .expect("validated front-channel origins produce a valid CSP");
    response
        .headers_mut()
        .insert(actix_web::http::header::CONTENT_SECURITY_POLICY, value);
}

#[derive(Clone)]
struct BackchannelLogoutRequest {
    uri: String,
    client_id: String,
    logout_token: String,
}

async fn dispatch_backchannel_logout(
    application: &Application,
    targets: Vec<crate::database::LogoutTarget>,
) {
    let snapshot = application.snapshot();
    let Some(database) = application.database() else {
        return;
    };
    let mut requests = Vec::new();
    for target in targets {
        let Some(client) = snapshot.client_for_issuer_url(&target.issuer, &target.client_id) else {
            tracing::warn!(
                event = "backchannel_logout",
                outcome = "skipped",
                client_id = %target.client_id,
                "session referenced an unconfigured client"
            );
            continue;
        };
        let Some(uri) = &client.backchannel_logout_uri else {
            continue;
        };
        let external_subject = match crate::pairwise::external_subject(
            &snapshot,
            &target.issuer,
            client,
            &target.subject,
        ) {
            Ok(subject) => subject,
            Err(error) => {
                tracing::error!(%error, client_id = %target.client_id, "failed to derive back-channel logout subject");
                continue;
            }
        };
        let key = match database.signing_key(&target.issuer).await {
            Ok(key) => key,
            Err(error) => {
                tracing::error!(%error, issuer = %target.issuer, "failed to load back-channel logout signing key");
                continue;
            }
        };
        let now = Utc::now().timestamp();
        let jti = random_token();
        let logout_token = match tokens::issue_logout_token(
            &key,
            &tokens::LogoutTokenInput {
                issuer: &target.issuer,
                subject: &external_subject,
                audience: &target.client_id,
                session_id: &target.session_id,
                jti: &jti,
                now,
                lifetime: 120,
            },
        ) {
            Ok(token) => token,
            Err(error) => {
                tracing::error!(%error, client_id = %target.client_id, "failed to sign back-channel logout token");
                continue;
            }
        };
        requests.push(BackchannelLogoutRequest {
            uri: uri.clone(),
            client_id: target.client_id,
            logout_token,
        });
    }

    let handles = requests
        .into_iter()
        .map(|request| {
            tokio::task::spawn_blocking(move || {
                let outcome = post_backchannel_logout(&request.uri, &request.logout_token);
                (request, outcome)
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        match handle.await {
            Ok((request, Ok(status))) if matches!(status, 200 | 204) => {
                tracing::info!(
                    event = "backchannel_logout",
                    outcome = "success",
                    client_id = %request.client_id,
                    status,
                    "RP accepted logout token"
                );
            }
            Ok((request, Ok(status))) => {
                tracing::warn!(
                    event = "backchannel_logout",
                    outcome = "rejected",
                    client_id = %request.client_id,
                    status,
                    "RP rejected logout token"
                );
            }
            Ok((request, Err(error))) => {
                tracing::warn!(
                    event = "backchannel_logout",
                    outcome = "failed",
                    client_id = %request.client_id,
                    %error,
                    "RP logout callback failed"
                );
            }
            Err(error) => tracing::warn!(%error, "back-channel logout worker failed"),
        }
    }
}

fn post_backchannel_logout(uri: &str, logout_token: &str) -> Result<u16, String> {
    use std::{
        io::{Read, Write},
        net::{TcpStream, ToSocketAddrs},
        sync::{Arc, OnceLock},
        time::Duration as StdDuration,
    };

    fn send<S: Read + Write>(
        stream: &mut S,
        host: &str,
        target: &str,
        body: &str,
    ) -> Result<u16, String> {
        let request = format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: robine-id-backchannel-logout/1\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .and_then(|_| stream.flush())
            .map_err(|error| error.to_string())?;
        let mut response = Vec::with_capacity(512);
        let mut buffer = [0_u8; 512];
        while response.len() < 8_192 && !response.windows(2).any(|bytes| bytes == b"\r\n") {
            let read = stream
                .read(&mut buffer)
                .map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..read]);
        }
        let status_line = response
            .split(|byte| *byte == b'\n')
            .next()
            .and_then(|line| std::str::from_utf8(line).ok())
            .ok_or_else(|| "RP returned an invalid HTTP response".to_owned())?;
        let mut parts = status_line.split_ascii_whitespace();
        if !parts
            .next()
            .is_some_and(|version| version.starts_with("HTTP/1."))
        {
            return Err("RP returned an invalid HTTP version".to_owned());
        }
        parts
            .next()
            .and_then(|status| status.parse::<u16>().ok())
            .filter(|status| (100..=599).contains(status))
            .ok_or_else(|| "RP returned an invalid HTTP status".to_owned())
    }

    let parsed = url::Url::parse(uri).map_err(|error| error.to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("unsupported back-channel logout URI scheme".to_owned());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "back-channel logout URI has no host".to_owned())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "back-channel logout URI has no port".to_owned())?;
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?;
    let timeout = StdDuration::from_secs(2);
    let mut last_error = None;
    let mut tcp = None;
    for address in addresses.take(8) {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut tcp = tcp.ok_or_else(|| {
        last_error.map_or_else(
            || "back-channel logout host did not resolve".to_owned(),
            |error| error.to_string(),
        )
    })?;
    tcp.set_read_timeout(Some(timeout))
        .and_then(|_| tcp.set_write_timeout(Some(timeout)))
        .map_err(|error| error.to_string())?;
    let target = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_owned(),
    };
    let target = if target.is_empty() { "/" } else { &target };
    let default_port = matches!((parsed.scheme(), port), ("https", 443) | ("http", 80));
    let host_header = match parsed.host() {
        Some(url::Host::Ipv6(address)) if default_port => format!("[{address}]"),
        Some(url::Host::Ipv6(address)) => format!("[{address}]:{port}"),
        Some(host) if default_port => host.to_string(),
        Some(host) => format!("{host}:{port}"),
        None => return Err("back-channel logout URI has no host".to_owned()),
    };
    let body = serde_urlencoded::to_string([("logout_token", logout_token)])
        .map_err(|error| error.to_string())?;

    match parsed.scheme() {
        "http" => send(&mut tcp, &host_header, target, &body),
        "https" => {
            static TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
            let configuration = TLS_CONFIG.get_or_init(|| {
                let roots = rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                );
                Arc::new(
                    rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth(),
                )
            });
            let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|error| error.to_string())?;
            let connection = rustls::ClientConnection::new(configuration.clone(), server_name)
                .map_err(|error| error.to_string())?;
            let mut stream = rustls::StreamOwned::new(connection, tcp);
            send(&mut stream, &host_header, target, &body)
        }
        _ => Err("unsupported back-channel logout URI scheme".to_owned()),
    }
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
            response_mode: pending.response_mode,
            resource: pending.resource,
            dpop_jkt: pending.dpop_jkt,
            session_id: pending.session_id,
            auth_time: pending.auth_time,
            mfa_verified: pending.mfa_verified,
            claims: pending.claims,
            authorization_details: pending.authorization_details,
            expires_at: pending.expires_at,
        }
    }
}

async fn authorization_success(
    database: &Database,
    grant: &AuthorizationGrant,
    state: &str,
    branding: &crate::configuration::Branding,
    request: &HttpRequest,
    session_absolute_timeout: i64,
) -> Result<HttpResponse, sqlx::Error> {
    let code = database.issue_authorization_code(grant).await?;
    let session_state = url::Url::parse(&grant.issuer)
        .is_ok_and(|issuer| issuer.scheme() == "https")
        .then(|| {
            grant.session_id.as_deref().and_then(|session_id| {
                new_session_state(&grant.client_id, &grant.redirect_uri, session_id)
            })
        })
        .flatten();
    let mut parameters = vec![
        ("code", code.as_str()),
        ("state", state),
        ("iss", grant.issuer.as_str()),
    ];
    if let Some(session_state) = session_state.as_deref() {
        parameters.push(("session_state", session_state));
    }
    let mut response = authorization_client_response(
        &grant.redirect_uri,
        grant.response_mode.as_deref(),
        &parameters,
        branding,
        Some((database, &grant.issuer, &grant.client_id)),
    )
    .await
    .map_err(sqlx::Error::Protocol)?;
    if session_state.is_some()
        && let Some(session_id) = grant.session_id.as_deref()
    {
        add_op_browser_state_cookie(
            &mut response,
            request,
            session_id,
            remaining_session_lifetime(grant.auth_time, session_absolute_timeout),
        );
    }
    Ok(response)
}

async fn authorization_denied(
    database: &Database,
    pending: &PendingAuthorization,
    branding: &crate::configuration::Branding,
    request: &HttpRequest,
    session_absolute_timeout: i64,
) -> HttpResponse {
    let session_state = url::Url::parse(&pending.issuer)
        .is_ok_and(|issuer| issuer.scheme() == "https")
        .then(|| {
            pending.session_id.as_deref().and_then(|session_id| {
                new_session_state(&pending.client_id, &pending.redirect_uri, session_id)
            })
        })
        .flatten();
    let mut parameters = vec![
        ("error", "access_denied"),
        ("error_description", "The resource owner denied the request"),
        ("state", pending.state.as_str()),
        ("iss", pending.issuer.as_str()),
    ];
    if let Some(session_state) = session_state.as_deref() {
        parameters.push(("session_state", session_state));
    }
    let mut response = authorization_client_response(
        &pending.redirect_uri,
        pending.response_mode.as_deref(),
        &parameters,
        branding,
        Some((database, &pending.issuer, &pending.client_id)),
    )
    .await
    .unwrap_or_else(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect URI is invalid",
        )
    });
    if session_state.is_some()
        && let Some(session_id) = pending.session_id.as_deref()
    {
        add_op_browser_state_cookie(
            &mut response,
            request,
            session_id,
            remaining_session_lifetime(pending.auth_time, session_absolute_timeout),
        );
    }
    response
}

async fn authorization_request_error(
    database: Option<&Database>,
    snapshot: &crate::configuration::Snapshot,
    branding: &crate::configuration::Branding,
    issuer_id: &str,
    request: &AuthorizationRequest,
    error: crate::protocol::AuthorizationError,
    request_id: &str,
) -> HttpResponse {
    let trusted_redirect = snapshot.issuer(issuer_id).is_some()
        && snapshot
            .client_for_issuer(issuer_id, &request.client_id)
            .is_some_and(|client| client.redirect_uris.contains(&request.redirect_uri));
    if !trusted_redirect {
        return protocol_error(branding, error.description, request_id);
    }
    let mut parameters = vec![
        ("error", error.code),
        ("error_description", error.description),
    ];
    if !request.state.is_empty() {
        parameters.push(("state", &request.state));
    }
    if let Some(issuer) = snapshot.issuer(issuer_id) {
        parameters.push(("iss", issuer.url.trim_end_matches('/')));
    }
    let issuer = snapshot
        .issuer(issuer_id)
        .map(|issuer| issuer.url.trim_end_matches('/'));
    authorization_client_response(
        &request.redirect_uri,
        request.response_mode.as_deref(),
        &parameters,
        branding,
        database
            .zip(issuer)
            .map(|(database, issuer)| (database, issuer, request.client_id.as_str())),
    )
    .await
    .unwrap_or_else(|_| protocol_error(branding, error.description, request_id))
}

async fn authorization_client_response(
    redirect_uri: &str,
    response_mode: Option<&str>,
    parameters: &[(&str, &str)],
    branding: &crate::configuration::Branding,
    jarm: Option<(&Database, &str, &str)>,
) -> Result<HttpResponse, String> {
    let signed_response;
    let signed_parameters;
    let (response_mode, parameters) =
        if matches!(response_mode, Some("jwt" | "query.jwt" | "form_post.jwt")) {
            let (database, issuer, client_id) =
                jarm.ok_or_else(|| "authorization response signing is unavailable".to_owned())?;
            let parameter = |name: &str| {
                parameters
                    .iter()
                    .find_map(|(candidate, value)| (*candidate == name).then_some(*value))
            };
            let key = database
                .signing_key(issuer)
                .await
                .map_err(|error| error.to_string())?;
            signed_response = tokens::issue_authorization_response(
                &key,
                &tokens::AuthorizationResponseInput {
                    issuer,
                    audience: client_id,
                    code: parameter("code"),
                    error: parameter("error"),
                    error_description: parameter("error_description"),
                    state: parameter("state"),
                    session_state: parameter("session_state"),
                    now: Utc::now().timestamp(),
                    lifetime: 60,
                },
            )
            .map_err(|error| error.to_string())?;
            signed_parameters = [("response", signed_response.as_str())];
            (
                if response_mode == Some("form_post.jwt") {
                    Some("form_post")
                } else {
                    Some("query")
                },
                signed_parameters.as_slice(),
            )
        } else {
            (response_mode, parameters)
        };
    let mut redirect = url::Url::parse(redirect_uri).map_err(|error| error.to_string())?;
    if response_mode != Some("form_post") {
        for (name, value) in parameters {
            redirect.query_pairs_mut().append_pair(name, value);
        }
        return Ok(redirect_response(redirect.to_string()));
    }

    let form_action = redirect.origin().ascii_serialization();
    if form_action == "null" {
        return Err("redirect URI has no web origin".to_owned());
    }
    let mut response = html_response(
        StatusCode::OK,
        FormPostTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            redirect_uri,
            parameters,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
        }
        .render(),
    );
    prevent_caching(&mut response);
    let content_security_policy = format!(
        "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data: https:; form-action {form_action}; base-uri 'none'; frame-ancestors 'none'"
    );
    let value = actix_web::http::header::HeaderValue::from_str(&content_security_policy)
        .map_err(|error| error.to_string())?;
    response
        .headers_mut()
        .insert(actix_web::http::header::CONTENT_SECURITY_POLICY, value);
    Ok(response)
}

async fn device_authorization(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<DeviceAuthorizationForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "unknown issuer");
    };
    let form = form.into_inner();
    let client = match authenticated_endpoint_client(
        &snapshot,
        &request,
        application.database(),
        issuer,
        EndpointClientAuthentication {
            form_id: form.client_id.as_deref(),
            form_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
            realm: "device_authorization",
            endpoint_path: "/device_authorization",
        },
    )
    .await
    {
        Ok(client) => client,
        Err(response) => return response,
    };
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == DEVICE_CODE_GRANT)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client does not allow device authorization",
        );
    }
    let scopes = match form.scope.as_deref() {
        Some(scope) if scope.len() <= 2_048 => normalized_scopes(scope),
        Some(_) => vec![],
        None => client
            .scopes
            .iter()
            .filter(|scope| scope.as_str() != "offline_access" && issuer.scopes.contains(scope))
            .cloned()
            .collect(),
    };
    if scopes.is_empty()
        || !scopes.iter().any(|scope| scope == "openid")
        || scopes
            .iter()
            .any(|scope| !issuer.scopes.contains(scope) || !client.scopes.contains(scope))
        || (scopes.iter().any(|scope| scope == "offline_access")
            && !client
                .grant_types
                .iter()
                .any(|grant| grant == "refresh_token"))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "one or more requested device scopes are not allowed",
        );
    }
    if form
        .resource
        .as_ref()
        .is_some_and(|resource| resource.len() > 4_096 || !client.resources.contains(resource))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "the requested resource is not registered for this client",
        );
    }
    let authorization_details = match crate::protocol::validated_authorization_details(
        form.authorization_details.as_deref(),
        &snapshot,
        client,
    ) {
        Ok(details) => details,
        Err(error) => {
            return oauth_error(StatusCode::BAD_REQUEST, error.code, error.description);
        }
    };
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    match database
        .issue_device_authorization(DeviceAuthorizationRequest {
            issuer: issuer.url.trim_end_matches('/'),
            client_id: &client.id,
            scopes: &scopes,
            resource: form.resource.as_deref(),
            authorization_details: &authorization_details,
            lifetime_seconds: issuer.token_policy.device_code_lifetime,
            poll_interval_seconds: issuer.token_policy.device_poll_interval,
        })
        .await
    {
        Ok((device_code, user_code)) => {
            application
                .metrics()
                .device_authorization(DeviceAuthorizationOutcome::Created);
            let verification_uri = format!("{}/device", issuer.url.trim_end_matches('/'));
            let mut complete = url::Url::parse(&verification_uri)
                .expect("validated issuer creates a valid device verification URI");
            complete
                .query_pairs_mut()
                .append_pair("user_code", &user_code);
            tracing::info!(
                event = "device_authorization",
                outcome = "created",
                issuer_id,
                client_id = %client.id,
                "device authorization created"
            );
            no_store_json_response(
                StatusCode::OK,
                json!({
                    "device_code": device_code,
                    "user_code": user_code,
                    "verification_uri": verification_uri,
                    "verification_uri_complete": complete.to_string(),
                    "expires_in": issuer.token_policy.device_code_lifetime,
                    "interval": issuer.token_policy.device_poll_interval
                }),
            )
        }
        Err(error) => {
            application
                .metrics()
                .device_authorization(DeviceAuthorizationOutcome::Rejected);
            tracing::error!(%error, "failed to create device authorization");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "device authorization storage failed",
            )
        }
    }
}

async fn device_verification(
    path: web::Path<String>,
    request: HttpRequest,
    query: web::Query<DeviceVerificationQuery>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    if snapshot.issuer(&issuer_id).is_none() {
        return json_response(StatusCode::NOT_FOUND, json!({"error": "not_found"}));
    }
    let user_code = query
        .user_code
        .as_deref()
        .and_then(normalize_device_user_code)
        .map(|(_, formatted)| formatted)
        .unwrap_or_default();
    render_device_code_page(
        &request,
        &snapshot,
        &issuer_id,
        &user_code,
        None,
        StatusCode::OK,
    )
}

async fn device_interaction(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<DeviceInteractionForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return json_response(StatusCode::NOT_FOUND, json!({"error": "not_found"}));
    };
    let form = form.into_inner();
    if !valid_csrf(&request, &form.csrf_token) {
        return protocol_error(
            &snapshot.configuration.branding,
            "The device form has expired; please start again",
            &correlation_id(&request),
        );
    }
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    match form.action.as_str() {
        "verify" => {
            let submitted = form.user_code.as_deref().unwrap_or_default();
            let Some((user_code, formatted_code)) = normalize_device_user_code(submitted) else {
                return render_device_code_page(
                    &request,
                    &snapshot,
                    &issuer_id,
                    "",
                    Some("invalid"),
                    StatusCode::UNPROCESSABLE_ENTITY,
                );
            };
            let remote = authentication_remote_address(&request, forwarded_headers_trusted());
            let rate_limit = &snapshot.configuration.authentication.rate_limit;
            match database
                .allow_authentication_attempt(
                    &format!("device-code:{issuer_id}:{remote}"),
                    rate_limit.attempts,
                    rate_limit.window_seconds,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    application.metrics().request_rate_limit_rejection();
                    return render_device_code_page(
                        &request,
                        &snapshot,
                        &issuer_id,
                        &formatted_code,
                        Some("rate_limited"),
                        StatusCode::TOO_MANY_REQUESTS,
                    );
                }
                Err(error) => {
                    tracing::error!(%error, "failed to rate-limit a device code attempt");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "device verification storage failed",
                    );
                }
            }
            let (transaction, authorization) = match database
                .begin_device_verification(&user_code, issuer.url.trim_end_matches('/'))
                .await
            {
                Ok(Some(result)) => result,
                Ok(None) => {
                    return render_device_code_page(
                        &request,
                        &snapshot,
                        &issuer_id,
                        &formatted_code,
                        Some("invalid"),
                        StatusCode::UNPROCESSABLE_ENTITY,
                    );
                }
                Err(error) => {
                    tracing::error!(%error, "failed to begin device verification");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "device verification storage failed",
                    );
                }
            };
            let Some(client) = active_device_authorization(&snapshot, issuer, &authorization)
            else {
                return render_device_code_page(
                    &request,
                    &snapshot,
                    &issuer_id,
                    &formatted_code,
                    Some("invalid"),
                    StatusCode::UNPROCESSABLE_ENTITY,
                );
            };
            let session = existing_session(&request, &application).await;
            let authenticated = session
                .subject
                .as_deref()
                .and_then(|subject| snapshot.user_for_issuer(&issuer_id, subject))
                .is_some_and(|user| {
                    (user.totp_secret_reference.is_none() || session.mfa_verified)
                        && authentication_context_satisfies(client, session.mfa_verified)
                });
            let mut response = render_device_confirmation(
                &request,
                &snapshot,
                &issuer_id,
                client,
                &authorization,
                &formatted_code,
                &transaction,
                authenticated,
                "",
                None,
                StatusCode::OK,
            );
            if session.clear_cookie {
                remove_session_cookie(&mut response, &request);
            }
            response
        }
        "decision" => {
            decide_device_interaction(
                &request,
                &application,
                &snapshot,
                issuer,
                &issuer_id,
                form,
                database,
            )
            .await
        }
        "totp" => {
            complete_device_totp(
                &request,
                &application,
                &snapshot,
                issuer,
                &issuer_id,
                form,
                database,
            )
            .await
        }
        _ => protocol_error(
            &snapshot.configuration.branding,
            "The device action is invalid",
            &correlation_id(&request),
        ),
    }
}

fn render_device_code_page(
    request: &HttpRequest,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    user_code: &str,
    error: Option<&str>,
    status: StatusCode,
) -> HttpResponse {
    let branding = snapshot.branding(Some(issuer_id), None);
    let messages = branding.messages(None);
    let error_message = match error {
        Some("invalid") => Some(messages.device_invalid_code.as_str()),
        Some("rate_limited") => Some(messages.sign_in_rate_limited.as_str()),
        _ => None,
    };
    let csrf_token = random_token();
    let mut response = html_response(
        status,
        DeviceCodeTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id,
            user_code,
            csrf_token: &csrf_token,
            has_error: error_message.is_some(),
            error: error_message,
            messages: &messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
            support_url: branding.support_url.as_deref(),
            privacy_url: branding.privacy_url.as_deref(),
            terms_url: branding.terms_url.as_deref(),
        }
        .render(),
    );
    add_csrf_cookie(&mut response, request, &csrf_token);
    response
}

#[allow(clippy::too_many_arguments)]
fn render_device_confirmation(
    request: &HttpRequest,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    client: &crate::configuration::Client,
    authorization: &DeviceAuthorization,
    user_code: &str,
    transaction: &str,
    authenticated: bool,
    identifier: &str,
    error: Option<&str>,
    status: StatusCode,
) -> HttpResponse {
    let branding = snapshot.branding(Some(issuer_id), Some(&client.id));
    let messages = branding.messages(None);
    let scopes = consent_scopes(&authorization.scopes, &messages);
    let authorization_details =
        consent_authorization_details(snapshot, &authorization.authorization_details);
    let csrf_token = random_token();
    let mut response = html_response(
        status,
        DeviceConfirmTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id,
            client_name: if client.name.is_empty() {
                &client.id
            } else {
                &client.name
            },
            user_code,
            scopes: &scopes,
            authorization_details: &authorization_details,
            transaction,
            csrf_token: &csrf_token,
            authenticated,
            identifier,
            has_error: error.is_some(),
            error,
            messages: &messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
        }
        .render(),
    );
    add_csrf_cookie(&mut response, request, &csrf_token);
    response
}

fn client_requires_mfa(client: &crate::configuration::Client) -> bool {
    client.required_acr.as_deref() == Some(crate::configuration::MFA_ACR)
}

fn authentication_context_satisfies(
    client: &crate::configuration::Client,
    mfa_verified: bool,
) -> bool {
    !client_requires_mfa(client) || mfa_verified
}

fn authorization_authentication_context_satisfies(
    client: &crate::configuration::Client,
    authorization: &AuthorizationRequest,
    mfa_verified: bool,
) -> bool {
    authentication_context_satisfies(client, mfa_verified)
        && authorization.authentication_context_satisfies(mfa_verified)
}

fn authorization_requires_mfa(
    client: &crate::configuration::Client,
    authorization: &AuthorizationRequest,
) -> bool {
    !authorization_authentication_context_satisfies(client, authorization, false)
        && authorization_authentication_context_satisfies(client, authorization, true)
}

fn authentication_max_age(
    client: &crate::configuration::Client,
    authorization: &AuthorizationRequest,
) -> Option<i64> {
    match (
        client.max_authentication_age,
        authorization.max_age_seconds(),
    ) {
        (Some(policy), Some(requested)) => Some(policy.min(requested)),
        (Some(policy), None) => Some(policy),
        (None, requested) => requested,
    }
}

fn essential_claims_satisfied(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    authorization: &AuthorizationRequest,
    user: &crate::configuration::User,
    auth_time: i64,
    mfa_verified: bool,
) -> bool {
    let scopes = normalized_scopes(&authorization.scope);
    let mapped = tokens::mapped_claims(snapshot, user, &scopes);
    let issuer = snapshot
        .issuer(issuer_id)
        .expect("validated authorization issuer");
    let essential_claims = authorization.essential_claims();
    let external_subject = if essential_claims.iter().any(|claim| claim.name == "sub") {
        let Some(client) = snapshot.client_for_issuer(issuer_id, &authorization.client_id) else {
            return false;
        };
        let Ok(subject) = crate::pairwise::external_subject(
            snapshot,
            issuer.url.trim_end_matches('/'),
            client,
            &user.id,
        ) else {
            return false;
        };
        Some(subject)
    } else {
        None
    };
    essential_claims.into_iter().all(|claim| {
        let actual = match claim.destination {
            crate::protocol::ClaimDestination::IdToken => match claim.name.as_str() {
                "sub" => external_subject.as_ref().map(|subject| json!(subject)),
                "iss" => Some(json!(issuer.url.trim_end_matches('/'))),
                "aud" => Some(json!(authorization.client_id)),
                "nonce" => (!authorization.nonce.is_empty()).then(|| json!(authorization.nonce)),
                "auth_time" => Some(json!(auth_time)),
                "acr" => Some(json!(if mfa_verified {
                    crate::configuration::MFA_ACR
                } else {
                    crate::configuration::PASSWORD_ACR
                })),
                "amr" => Some(if mfa_verified {
                    json!(["pwd", "otp"])
                } else {
                    json!(["pwd"])
                }),
                "iat" | "exp" | "at_hash" => Some(Value::Null),
                name => mapped.get(name).cloned(),
            },
            crate::protocol::ClaimDestination::UserInfo => match claim.name.as_str() {
                "sub" => external_subject.as_ref().map(|subject| json!(subject)),
                name => mapped.get(name).cloned(),
            },
        };
        actual.is_some_and(|actual| {
            claim.accepted_values.is_empty()
                || (actual != Value::Null && claim.accepted_values.contains(&actual))
        })
    })
}

fn active_device_authorization<'a>(
    snapshot: &'a crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    authorization: &DeviceAuthorization,
) -> Option<&'a crate::configuration::Client> {
    let client = snapshot.client_for_issuer(&issuer.id, &authorization.client_id)?;
    (authorization.issuer == issuer.url.trim_end_matches('/')
        && authorization.expires_at > Utc::now()
        && client
            .grant_types
            .iter()
            .any(|grant| grant == DEVICE_CODE_GRANT)
        && authorization.scopes.iter().any(|scope| scope == "openid")
        && authorization
            .scopes
            .iter()
            .all(|scope| issuer.scopes.contains(scope) && client.scopes.contains(scope))
        && authorization
            .resource
            .as_ref()
            .is_none_or(|resource| client.resources.contains(resource)))
    .then_some(client)
}

#[allow(clippy::too_many_arguments)]
fn render_device_totp_challenge(
    request: &HttpRequest,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    client: &crate::configuration::Client,
    transaction: &str,
    csrf_token: &str,
    error: Option<&str>,
    status: StatusCode,
) -> HttpResponse {
    let branding = snapshot.branding(Some(issuer_id), Some(&client.id));
    let messages = branding.messages(None);
    let form_action = format!("/{issuer_id}/device");
    let mut response = html_response(
        status,
        TotpTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            client_name: if client.name.is_empty() {
                &client.id
            } else {
                &client.name
            },
            transaction,
            form_action: &form_action,
            transaction_field: "mfa_transaction",
            action_value: Some("totp"),
            csrf_token,
            has_error: error.is_some(),
            error,
            messages: &messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
            support_url: branding.support_url.as_deref(),
            privacy_url: branding.privacy_url.as_deref(),
            terms_url: branding.terms_url.as_deref(),
        }
        .render(),
    );
    add_csrf_cookie(&mut response, request, csrf_token);
    response
}

#[allow(clippy::too_many_arguments)]
async fn complete_device_totp(
    request: &HttpRequest,
    application: &Application,
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    issuer_id: &str,
    form: DeviceInteractionForm,
    database: &Database,
) -> HttpResponse {
    let (Some(transaction), Some(submitted_code)) =
        (form.mfa_transaction.as_deref(), form.totp_code.as_deref())
    else {
        return protocol_error(
            &snapshot.configuration.branding,
            "The device verification is incomplete",
            &correlation_id(request),
        );
    };
    if form.transaction.is_some()
        || form.user_code.is_some()
        || form.decision.is_some()
        || form.identifier.is_some()
        || form.password.is_some()
    {
        return protocol_error(
            &snapshot.configuration.branding,
            "The device verification is invalid",
            &correlation_id(request),
        );
    }
    let issuer_url = issuer.url.trim_end_matches('/');
    let challenge = match database
        .totp_challenge(transaction, issuer_url, "device")
        .await
    {
        Ok(Some(challenge)) => challenge,
        Ok(None) => {
            let message = snapshot
                .branding(Some(issuer_id), None)
                .messages(None)
                .totp_expired;
            return protocol_error(
                &snapshot.configuration.branding,
                &message,
                &correlation_id(request),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load device TOTP challenge");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "multi-factor authentication storage failed",
            );
        }
    };
    let payload = match serde_json::from_value::<DeviceTotpPayload>(challenge.payload) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::error!(%error, "stored device TOTP challenge is invalid");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "multi-factor authentication storage failed",
            );
        }
    };
    let authorization = match database
        .device_verification_by_transaction(&payload.device_transaction)
        .await
    {
        Ok(Some(authorization)) => authorization,
        Ok(None) => {
            return protocol_error(
                &snapshot.configuration.branding,
                "The device confirmation has expired",
                &correlation_id(request),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load device verification during TOTP");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "device verification storage failed",
            );
        }
    };
    let Some(client) = active_device_authorization(snapshot, issuer, &authorization) else {
        return protocol_error(
            &snapshot.configuration.branding,
            "The device confirmation is no longer valid",
            &correlation_id(request),
        );
    };
    let Some(user) = snapshot.user_for_issuer(issuer_id, &challenge.subject) else {
        return protocol_error(
            &snapshot.configuration.branding,
            "This verification is no longer valid",
            &correlation_id(request),
        );
    };
    let Some(reference) = user.totp_secret_reference.as_ref() else {
        return protocol_error(
            &snapshot.configuration.branding,
            "This verification is no longer valid",
            &correlation_id(request),
        );
    };
    let branding = snapshot.branding(Some(issuer_id), Some(&client.id));
    let messages = branding.messages(None);
    let remote = authentication_remote_address(request, forwarded_headers_trusted());
    let keys = authentication_rate_limit_keys(issuer_id, &remote, Some(&user.identifier));
    let rate_limit = &snapshot.configuration.authentication.rate_limit;
    match database
        .allow_authentication_attempts(&keys, rate_limit.attempts, rate_limit.window_seconds)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            application.metrics().rate_limit_rejection();
            return render_device_totp_challenge(
                request,
                snapshot,
                issuer_id,
                client,
                transaction,
                &form.csrf_token,
                Some(&messages.sign_in_rate_limited),
                StatusCode::TOO_MANY_REQUESTS,
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to rate-limit device TOTP authentication");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "authentication storage failed",
            );
        }
    }
    let secret = match crate::totp::secret_from_reference(reference) {
        Ok(secret) => secret,
        Err(error) => {
            tracing::error!(?error, "configured TOTP secret is unavailable");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "multi-factor authentication is unavailable",
            );
        }
    };
    let Some(counter) = crate::totp::verify(&secret, submitted_code, Utc::now().timestamp()) else {
        application.metrics().authentication(false);
        application.metrics().mfa(MfaOutcome::Failure);
        return render_device_totp_challenge(
            request,
            snapshot,
            issuer_id,
            client,
            transaction,
            &form.csrf_token,
            Some(&messages.totp_invalid_code),
            StatusCode::UNPROCESSABLE_ENTITY,
        );
    };
    match database
        .consume_totp_challenge(transaction, issuer_url, &user.id, "device", counter)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            application.metrics().authentication(false);
            application.metrics().mfa(MfaOutcome::Rejected);
            let message = snapshot
                .branding(Some(issuer_id), Some(&client.id))
                .messages(None)
                .totp_expired;
            return protocol_error(
                &snapshot.configuration.branding,
                &message,
                &correlation_id(request),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to consume device TOTP challenge");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "multi-factor authentication storage failed",
            );
        }
    }
    application.metrics().mfa(MfaOutcome::Success);
    let approved = match payload.decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => {
            return protocol_error(
                &snapshot.configuration.branding,
                "The device decision is invalid",
                &correlation_id(request),
            );
        }
    };
    let claims = if approved {
        Value::Object(tokens::mapped_claims(snapshot, user, &authorization.scopes))
    } else {
        json!({})
    };
    let session_policy = &snapshot.configuration.authentication.session;
    let session = match database
        .start_session_details(
            &user.id,
            session_policy.max_concurrent.max(1),
            session_policy.absolute_timeout.max(1),
            true,
        )
        .await
    {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(%error, "failed to start MFA device verification session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "session storage failed",
            );
        }
    };
    match database
        .decide_device_authorization(
            &payload.device_transaction,
            DeviceAuthorizationDecision {
                subject: &user.id,
                claims: &claims,
                auth_time: Utc::now().timestamp(),
                session_id: Some(&session.session_id),
                approved,
                mfa_verified: true,
            },
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return protocol_error(
                &snapshot.configuration.branding,
                "The device confirmation has expired",
                &correlation_id(request),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to persist device decision after TOTP");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "device verification storage failed",
            );
        }
    }
    application.metrics().authentication(true);
    application.metrics().device_authorization(if approved {
        DeviceAuthorizationOutcome::Approved
    } else {
        DeviceAuthorizationOutcome::Denied
    });
    tracing::info!(
        event = "device_authorization",
        outcome = if approved { "approved" } else { "denied" },
        issuer_id,
        client_id = %client.id,
        mfa_verified = true,
        "device authorization decision completed"
    );
    let mut response = html_response(
        StatusCode::OK,
        DeviceDoneTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            approved,
            messages: &messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
        }
        .render(),
    );
    add_session_cookie(
        &mut response,
        request,
        &session.token,
        &session.session_id,
        session_policy.absolute_timeout,
    );
    response
}

#[allow(clippy::too_many_arguments)]
async fn decide_device_interaction(
    request: &HttpRequest,
    application: &Application,
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    issuer_id: &str,
    form: DeviceInteractionForm,
    database: &Database,
) -> HttpResponse {
    let Some(transaction) = form
        .transaction
        .as_deref()
        .filter(|value| valid_opaque_token(value))
    else {
        return protocol_error(
            &snapshot.configuration.branding,
            "The device confirmation has expired",
            &correlation_id(request),
        );
    };
    let Some((user_code, formatted_code)) = form
        .user_code
        .as_deref()
        .and_then(normalize_device_user_code)
    else {
        return protocol_error(
            &snapshot.configuration.branding,
            "The device confirmation is invalid",
            &correlation_id(request),
        );
    };
    let authorization = match database.device_verification(transaction, &user_code).await {
        Ok(Some(authorization)) => authorization,
        Ok(None) => {
            return protocol_error(
                &snapshot.configuration.branding,
                "The device confirmation has expired",
                &correlation_id(request),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load device verification");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "device verification storage failed",
            );
        }
    };
    let Some(client) = active_device_authorization(snapshot, issuer, &authorization) else {
        return protocol_error(
            &snapshot.configuration.branding,
            "The device confirmation is no longer valid",
            &correlation_id(request),
        );
    };
    let approved = match form.decision.as_deref() {
        Some("approve") => true,
        Some("deny") => false,
        _ => {
            return protocol_error(
                &snapshot.configuration.branding,
                "The device decision is invalid",
                &correlation_id(request),
            );
        }
    };
    let session = existing_session(request, application).await;
    if session.unavailable {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "session storage failed",
        );
    }
    let session_user = session
        .subject
        .as_deref()
        .and_then(|subject| snapshot.user_for_issuer(issuer_id, subject))
        .filter(|user| user.totp_secret_reference.is_none() || session.mfa_verified)
        .filter(|_| authentication_context_satisfies(client, session.mfa_verified))
        .cloned();
    let mut new_session = None;
    let mfa_verified = session.mfa_verified;
    let user = if let Some(user) = session_user {
        user
    } else {
        let submitted_identifier = form.identifier.as_deref().unwrap_or_default().trim();
        let identifier_valid = valid_submitted_identifier(submitted_identifier);
        let identifier = if identifier_valid {
            submitted_identifier
        } else {
            ""
        };
        let remote = authentication_remote_address(request, forwarded_headers_trusted());
        let keys = authentication_rate_limit_keys(
            issuer_id,
            &remote,
            identifier_valid.then_some(submitted_identifier),
        );
        let rate_limit = &snapshot.configuration.authentication.rate_limit;
        match database
            .allow_authentication_attempts(&keys, rate_limit.attempts, rate_limit.window_seconds)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                application.metrics().rate_limit_rejection();
                return render_device_confirmation(
                    request,
                    snapshot,
                    issuer_id,
                    client,
                    &authorization,
                    &formatted_code,
                    transaction,
                    false,
                    identifier,
                    Some(
                        &snapshot
                            .branding(Some(issuer_id), Some(&client.id))
                            .messages(None)
                            .sign_in_rate_limited,
                    ),
                    StatusCode::TOO_MANY_REQUESTS,
                );
            }
            Err(error) => {
                tracing::error!(%error, "failed to rate-limit device authentication");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "authentication storage failed",
                );
            }
        }
        let user = identifier_valid
            .then(|| {
                snapshot
                    .user_by_identifier_for_issuer(issuer_id, identifier)
                    .cloned()
            })
            .flatten();
        let hash = user
            .as_ref()
            .map(|user| user.password_hash.clone())
            .unwrap_or_else(|| snapshot.dummy_password_hash().to_owned());
        let password = form.password.as_deref().unwrap_or_default();
        let password = if valid_submitted_password(password) {
            password.to_owned()
        } else {
            "invalid-credential-shape".to_owned()
        };
        let verified = web::block(move || bcrypt::verify(password, &hash).unwrap_or(false))
            .await
            .unwrap_or(false);
        let Some(user) = user.filter(|_| verified) else {
            application.metrics().authentication(false);
            let message = snapshot
                .branding(Some(issuer_id), Some(&client.id))
                .messages(None)
                .sign_in_invalid_credentials;
            return render_device_confirmation(
                request,
                snapshot,
                issuer_id,
                client,
                &authorization,
                &formatted_code,
                transaction,
                false,
                identifier,
                Some(&message),
                StatusCode::UNPROCESSABLE_ENTITY,
            );
        };
        if client_requires_mfa(client) && user.totp_secret_reference.is_none() {
            application.metrics().authentication(false);
            application.metrics().mfa(MfaOutcome::Rejected);
            let message = snapshot
                .branding(Some(issuer_id), Some(&client.id))
                .messages(None)
                .sign_in_mfa_required;
            return render_device_confirmation(
                request,
                snapshot,
                issuer_id,
                client,
                &authorization,
                &formatted_code,
                transaction,
                false,
                identifier,
                Some(&message),
                StatusCode::FORBIDDEN,
            );
        }
        if let Some(reference) = &user.totp_secret_reference {
            if let Err(error) = crate::totp::secret_from_reference(reference) {
                tracing::error!(?error, "configured TOTP secret is unavailable");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "multi-factor authentication is unavailable",
                );
            }
            let payload = serde_json::to_value(DeviceTotpPayload {
                device_transaction: transaction.to_owned(),
                decision: if approved { "approve" } else { "deny" }.to_owned(),
            })
            .expect("device TOTP challenge serializes");
            let mfa_transaction = match database
                .issue_totp_challenge(
                    issuer.url.trim_end_matches('/'),
                    &user.id,
                    "device",
                    &payload,
                    issuer.token_policy.device_code_lifetime,
                )
                .await
            {
                Ok(transaction) => transaction,
                Err(error) => {
                    tracing::error!(%error, "failed to persist device TOTP challenge");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "multi-factor authentication storage failed",
                    );
                }
            };
            application.metrics().mfa(MfaOutcome::Challenged);
            return render_device_totp_challenge(
                request,
                snapshot,
                issuer_id,
                client,
                &mfa_transaction,
                &form.csrf_token,
                None,
                StatusCode::OK,
            );
        }
        let session_policy = &snapshot.configuration.authentication.session;
        match database
            .start_session_details(
                &user.id,
                session_policy.max_concurrent.max(1),
                session_policy.absolute_timeout.max(1),
                false,
            )
            .await
        {
            Ok(session) => new_session = Some(session),
            Err(error) => {
                tracing::error!(%error, "failed to start device verification session");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "session storage failed",
                );
            }
        }
        application.metrics().authentication(true);
        user
    };
    let claims = if approved {
        Value::Object(tokens::mapped_claims(
            snapshot,
            &user,
            &authorization.scopes,
        ))
    } else {
        json!({})
    };
    let session_id = new_session
        .as_ref()
        .map(|session| session.session_id.as_str())
        .or(session.session_id.as_deref());
    match database
        .decide_device_authorization(
            transaction,
            DeviceAuthorizationDecision {
                subject: &user.id,
                claims: &claims,
                auth_time: Utc::now().timestamp(),
                session_id,
                approved,
                mfa_verified,
            },
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return protocol_error(
                &snapshot.configuration.branding,
                "The device confirmation has expired",
                &correlation_id(request),
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to persist device decision");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "device verification storage failed",
            );
        }
    }
    if approved {
        tracing::info!(
            event = "device_authorization",
            outcome = "approved",
            issuer_id,
            client_id = %client.id,
            subject_id = %user.id,
            "device authorization approved"
        );
    } else {
        tracing::info!(
            event = "device_authorization",
            outcome = "denied",
            issuer_id,
            client_id = %client.id,
            "device authorization denied"
        );
    }
    application.metrics().device_authorization(if approved {
        DeviceAuthorizationOutcome::Approved
    } else {
        DeviceAuthorizationOutcome::Denied
    });
    let branding = snapshot.branding(Some(issuer_id), Some(&client.id));
    let messages = branding.messages(None);
    let mut response = html_response(
        StatusCode::OK,
        DeviceDoneTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            approved,
            messages: &messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
        }
        .render(),
    );
    if let Some(session) = new_session {
        add_session_cookie(
            &mut response,
            request,
            &session.token,
            &session.session_id,
            snapshot
                .configuration
                .authentication
                .session
                .absolute_timeout,
        );
    } else if session.clear_cookie {
        remove_session_cookie(&mut response, request);
    }
    response
}

fn normalize_device_user_code(value: &str) -> Option<(String, String)> {
    const ALPHABET: &str = "BCDFGHJKLMNPQRSTVWXY";
    let mut normalized = String::with_capacity(8);
    for character in value.trim().chars() {
        if character == '-' || character.is_ascii_whitespace() {
            continue;
        }
        let character = character.to_ascii_uppercase();
        if !ALPHABET.contains(character) || normalized.len() == 8 {
            return None;
        }
        normalized.push(character);
    }
    (normalized.len() == 8).then(|| {
        let formatted = format!("{}-{}", &normalized[..4], &normalized[4..]);
        (normalized, formatted)
    })
}

async fn exchange_token(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<TokenForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.as_str().to_owned();
    let metrics_application = application.clone();
    let cors_snapshot = application.snapshot();
    let cors_request = request.clone();
    let cors_client_id = form.client_id.clone();
    let token_grant = TokenGrant::from_grant_type(&form.grant_type);
    let mut response = exchange_token_inner(path, request, form, application).await;
    add_token_cors(
        &mut response,
        &cors_request,
        &cors_snapshot,
        &issuer_id,
        cors_client_id.as_deref(),
    );
    let success = response.status().is_success();
    metrics_application
        .metrics()
        .token_issuance(token_grant, success);
    if token_grant == TokenGrant::TokenExchange {
        metrics_application.metrics().token_exchange(success);
    }
    if !success {
        let event = token_audit_event(token_grant);
        tracing::warn!(
            event,
            outcome = "failure",
            issuer_id,
            grant_type = token_grant.label(),
            status = response.status().as_u16(),
            "token request rejected"
        );
    }
    response
}

fn token_audit_event(grant: TokenGrant) -> &'static str {
    if grant == TokenGrant::TokenExchange {
        "token_exchange"
    } else {
        "token_issuance"
    }
}

async fn token_options(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    if snapshot.issuer(&issuer_id).is_none() {
        return json_response(StatusCode::NOT_FOUND, json!({"error": "not_found"}));
    }
    let requested_method = request
        .headers()
        .get("access-control-request-method")
        .and_then(|value| value.to_str().ok());
    let requested_headers_supported = request
        .headers()
        .get("access-control-request-headers")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|headers| {
            headers.split(',').all(|header| {
                matches!(
                    header.trim().to_ascii_lowercase().as_str(),
                    "content-type" | "dpop"
                )
            })
        });
    let origin = request
        .headers()
        .get(actix_web::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if !requested_method.is_some_and(|method| method.eq_ignore_ascii_case("POST"))
        || !requested_headers_supported
        || !origin.is_some_and(|origin| token_origin_allowed(&snapshot, &issuer_id, origin, None))
    {
        return no_store_empty_response(StatusCode::FORBIDDEN);
    }

    let mut response = HttpResponse::NoContent().finish();
    add_token_cors(&mut response, &request, &snapshot, &issuer_id, None);
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("access-control-allow-methods"),
        actix_web::http::header::HeaderValue::from_static("POST"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("access-control-allow-headers"),
        actix_web::http::header::HeaderValue::from_static("Content-Type, DPoP"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("access-control-max-age"),
        actix_web::http::header::HeaderValue::from_static("600"),
    );
    response
}

async fn revocation_options(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    if snapshot.issuer(&issuer_id).is_none() {
        return json_response(StatusCode::NOT_FOUND, json!({"error": "not_found"}));
    }
    let requested_method = request
        .headers()
        .get("access-control-request-method")
        .and_then(|value| value.to_str().ok());
    let requested_headers_supported = request
        .headers()
        .get("access-control-request-headers")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|headers| {
            headers
                .split(',')
                .all(|header| header.trim().eq_ignore_ascii_case("content-type"))
        });
    let origin = request
        .headers()
        .get(actix_web::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if !requested_method.is_some_and(|method| method.eq_ignore_ascii_case("POST"))
        || !requested_headers_supported
        || !origin
            .is_some_and(|origin| revocation_origin_allowed(&snapshot, &issuer_id, origin, None))
    {
        return no_store_empty_response(StatusCode::FORBIDDEN);
    }

    let mut response = HttpResponse::NoContent().finish();
    add_revocation_cors(&mut response, &request, &snapshot, &issuer_id, None);
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("access-control-allow-methods"),
        actix_web::http::header::HeaderValue::from_static("POST"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("access-control-allow-headers"),
        actix_web::http::header::HeaderValue::from_static("Content-Type"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("access-control-max-age"),
        actix_web::http::header::HeaderValue::from_static("600"),
    );
    response
}

async fn exchange_token_inner(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<TokenForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "unknown issuer");
    };
    let form = form.into_inner();
    if !matches!(
        form.grant_type.as_str(),
        "authorization_code"
            | "refresh_token"
            | "client_credentials"
            | TOKEN_EXCHANGE_GRANT
            | DEVICE_CODE_GRANT
    ) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "the requested grant type is not supported",
        );
    }
    if (form.grant_type == "authorization_code"
        && (form.code.as_deref().is_none_or(str::is_empty)
            || form.redirect_uri.as_deref().is_none_or(str::is_empty)))
        || (form.grant_type == "refresh_token"
            && form.refresh_token.as_deref().is_none_or(str::is_empty))
        || (form.grant_type == DEVICE_CODE_GRANT
            && form.device_code.as_deref().is_none_or(str::is_empty))
        || (form.grant_type == TOKEN_EXCHANGE_GRANT
            && (form.subject_token.as_deref().is_none_or(str::is_empty)
                || form.subject_token_type.as_deref().is_none_or(str::is_empty)))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the token request is incomplete",
        );
    }
    let client = match authenticated_endpoint_client(
        &snapshot,
        &request,
        application.database(),
        issuer,
        EndpointClientAuthentication {
            form_id: form.client_id.as_deref(),
            form_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
            realm: "token",
            endpoint_path: "/token",
        },
    )
    .await
    {
        Ok(client) => client,
        Err(response) => return response,
    };
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let dpop = match verified_dpop_endpoint_proof(
        &request,
        database,
        issuer,
        "/token",
        "authorization_server",
        None,
    )
    .await
    {
        Ok(proof) => proof,
        Err(DpopProofError::Invalid) => {
            return invalid_dpop_proof_response("the DPoP proof is invalid or has been replayed");
        }
        Err(DpopProofError::NonceRequired(nonce)) => {
            return dpop_nonce_response(false, &nonce);
        }
        Err(DpopProofError::Unavailable) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "DPoP replay storage unavailable",
            );
        }
    };

    match form.grant_type.as_str() {
        "authorization_code" => {
            exchange_authorization_code_grant(
                &issuer_id,
                &snapshot,
                issuer,
                client,
                &form,
                database,
                dpop.as_ref(),
            )
            .await
        }
        "refresh_token" => {
            exchange_refresh_token_grant(
                &issuer_id,
                &snapshot,
                issuer,
                client,
                &form,
                database,
                dpop.as_ref(),
            )
            .await
        }
        "client_credentials" => {
            exchange_client_credentials_grant(
                &issuer_id,
                &snapshot,
                issuer,
                client,
                &form,
                database,
                dpop.as_ref(),
            )
            .await
        }
        DEVICE_CODE_GRANT => {
            exchange_device_code_grant(
                &issuer_id,
                &snapshot,
                issuer,
                client,
                &form,
                database,
                dpop.as_ref(),
                application.metrics(),
            )
            .await
        }
        TOKEN_EXCHANGE_GRANT => {
            exchange_access_token_grant(
                &issuer_id,
                &snapshot,
                issuer,
                client,
                &form,
                database,
                dpop.as_ref(),
            )
            .await
        }
        _ => unreachable!("grant type checked above"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn exchange_device_code_grant(
    issuer_id: &str,
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    client: &crate::configuration::Client,
    form: &TokenForm,
    database: &Database,
    dpop: Option<&tokens::VerifiedDpopProof>,
    metrics: &crate::metrics::Metrics,
) -> HttpResponse {
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == DEVICE_CODE_GRANT)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client does not allow the device authorization grant",
        );
    }
    let Some(device_code) = form.device_code.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "device_code is required",
        );
    };
    if !valid_opaque_token(device_code) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device code is invalid",
        );
    }
    let requested_authorization_details = match token_authorization_details(form, snapshot, client)
    {
        Ok(details) => details,
        Err(response) => return response,
    };
    let grant = match database
        .poll_device_authorization(device_code, issuer.url.trim_end_matches('/'), &client.id)
        .await
    {
        Ok(DevicePoll::Approved(grant)) => *grant,
        Ok(DevicePoll::Pending) => {
            metrics.device_authorization(DeviceAuthorizationOutcome::Pending);
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "authorization_pending",
                "the user has not completed device authorization",
            );
        }
        Ok(DevicePoll::SlowDown) => {
            metrics.device_authorization(DeviceAuthorizationOutcome::SlowDown);
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "slow_down",
                "the client is polling faster than the permitted interval",
            );
        }
        Ok(DevicePoll::Denied) => {
            metrics.device_authorization(DeviceAuthorizationOutcome::Denied);
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "the user denied the device authorization request",
            );
        }
        Ok(DevicePoll::Expired) => {
            metrics.device_authorization(DeviceAuthorizationOutcome::Rejected);
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "the device code has expired",
            );
        }
        Ok(DevicePoll::Invalid) => {
            metrics.device_authorization(DeviceAuthorizationOutcome::Rejected);
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "device code is invalid",
            );
        }
        Err(error) => {
            metrics.device_authorization(DeviceAuthorizationOutcome::Rejected);
            tracing::error!(%error, "failed to poll device authorization");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "device authorization storage failed",
            );
        }
    };

    let currently_valid = grant.issuer == issuer.url.trim_end_matches('/')
        && grant.client_id == client.id
        && grant.expires_at > Utc::now()
        && snapshot
            .user_for_issuer(&issuer.id, &grant.subject)
            .is_some()
        && grant.scopes.iter().any(|scope| scope == "openid")
        && grant
            .scopes
            .iter()
            .all(|scope| issuer.scopes.contains(scope) && client.scopes.contains(scope))
        && grant
            .resource
            .as_ref()
            .is_none_or(|resource| client.resources.contains(resource))
        && authorization_details_currently_allowed(snapshot, client, &grant.authorization_details);
    if !currently_valid {
        metrics.device_authorization(DeviceAuthorizationOutcome::Rejected);
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device authorization grant is no longer active",
        );
    }

    let authorization_details = match requested_authorization_details {
        Some(requested)
            if !authorization_details_subset(&requested, &grant.authorization_details) =>
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_authorization_details",
                "requested authorization_details exceeds the device grant",
            );
        }
        Some(requested) => requested,
        None => grant.authorization_details.clone(),
    };

    let dpop_jkt = dpop.map(|proof| proof.jkt.clone());
    let claims = refresh_claims(snapshot, &grant.scopes, grant.claims);
    let refresh_token = if grant.scopes.iter().any(|scope| scope == "offline_access") {
        if !client
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
        {
            metrics.device_authorization(DeviceAuthorizationOutcome::Rejected);
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "offline access is no longer allowed for this client",
            );
        }
        let refresh_grant = RefreshGrant {
            issuer: grant.issuer.clone(),
            subject: grant.subject.clone(),
            client_id: grant.client_id.clone(),
            scopes: grant.scopes.clone(),
            resource: grant.resource.clone(),
            dpop_jkt: (client.client_type == "public")
                .then(|| dpop_jkt.clone())
                .flatten(),
            session_id: grant.session_id.clone(),
            auth_time: grant.auth_time,
            mfa_verified: grant.mfa_verified,
            claims: claims.clone(),
            authorization_details: authorization_details.clone(),
            expires_at: Utc::now() + Duration::seconds(issuer.token_policy.refresh_token_lifetime),
        };
        match database.issue_refresh_token(&refresh_grant).await {
            Ok(token) => Some(token),
            Err(error) => {
                metrics.device_authorization(DeviceAuthorizationOutcome::Rejected);
                tracing::error!(%error, "failed to issue device refresh token");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "token storage failed",
                );
            }
        }
    } else {
        None
    };

    let response = issue_token_response(
        issuer_id,
        snapshot,
        issuer,
        database,
        TokenIssue {
            issuer: grant.issuer,
            subject: grant.subject,
            client_id: grant.client_id,
            scopes: grant.scopes,
            resource: grant.resource,
            dpop_jkt,
            session_id: grant.session_id,
            nonce: None,
            auth_time: grant.auth_time,
            mfa_verified: grant.mfa_verified,
            claims,
            authorization_details,
        },
        refresh_token,
        DEVICE_CODE_GRANT,
    )
    .await;
    metrics.device_authorization(if response.status().is_success() {
        DeviceAuthorizationOutcome::TokenIssued
    } else {
        DeviceAuthorizationOutcome::Rejected
    });
    response
}

struct TokenIssue {
    issuer: String,
    subject: String,
    client_id: String,
    scopes: Vec<String>,
    resource: Option<String>,
    dpop_jkt: Option<String>,
    session_id: Option<String>,
    nonce: Option<String>,
    auth_time: Option<i64>,
    mfa_verified: bool,
    claims: Value,
    authorization_details: Value,
}

async fn exchange_authorization_code_grant(
    issuer_id: &str,
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    client: &crate::configuration::Client,
    form: &TokenForm,
    database: &Database,
    dpop: Option<&tokens::VerifiedDpopProof>,
) -> HttpResponse {
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client does not allow authorization_code",
        );
    }
    let (Some(code), Some(redirect_uri)) = (form.code.as_deref(), form.redirect_uri.as_deref())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code and redirect_uri are required",
        );
    };
    if code.is_empty() || code.len() > 4_096 || redirect_uri.len() > 4_096 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization code parameters are invalid",
        );
    }
    let requested_authorization_details = match token_authorization_details(form, snapshot, client)
    {
        Ok(details) => details,
        Err(response) => return response,
    };
    let grant = match database.consume_authorization_code(code).await {
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
        || grant.client_id != client.id
        || grant.redirect_uri != redirect_uri
        || grant
            .resource
            .as_ref()
            .is_some_and(|resource| !client.resources.contains(resource))
        || !authorization_details_currently_allowed(snapshot, client, &grant.authorization_details)
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
    let authorization_details = match requested_authorization_details {
        Some(requested)
            if !authorization_details_subset(&requested, &grant.authorization_details) =>
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_authorization_details",
                "requested authorization_details exceeds the authorization grant",
            );
        }
        Some(requested) => requested,
        None => grant.authorization_details.clone(),
    };
    if form.resource.as_ref() != grant.resource.as_ref() && form.resource.is_some() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "the requested resource does not match the authorization grant",
        );
    }
    if grant
        .dpop_jkt
        .as_deref()
        .is_some_and(|expected| dpop.map(|proof| proof.jkt.as_str()) != Some(expected))
    {
        return invalid_dpop_proof_response(
            "the DPoP proof does not match the authorization grant",
        );
    }
    let access_dpop_jkt = dpop.map(|proof| proof.jkt.clone());
    let refresh_token = if grant.scopes.iter().any(|scope| scope == "offline_access") {
        if !client
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "offline access is no longer allowed for this client",
            );
        }
        let refresh_grant = RefreshGrant {
            issuer: grant.issuer.clone(),
            subject: grant.subject.clone(),
            client_id: grant.client_id.clone(),
            scopes: grant.scopes.clone(),
            resource: grant.resource.clone(),
            dpop_jkt: (client.client_type == "public")
                .then(|| access_dpop_jkt.clone())
                .flatten(),
            session_id: grant.session_id.clone(),
            auth_time: grant.auth_time,
            mfa_verified: grant.mfa_verified,
            claims: grant.claims.clone(),
            authorization_details: authorization_details.clone(),
            expires_at: Utc::now() + Duration::seconds(issuer.token_policy.refresh_token_lifetime),
        };
        match database.issue_refresh_token(&refresh_grant).await {
            Ok(token) => Some(token),
            Err(error) => {
                tracing::error!(%error, "failed to issue refresh token");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "token storage failed",
                );
            }
        }
    } else {
        None
    };
    issue_token_response(
        issuer_id,
        snapshot,
        issuer,
        database,
        TokenIssue {
            issuer: grant.issuer,
            subject: grant.subject,
            client_id: grant.client_id,
            scopes: grant.scopes,
            resource: grant.resource,
            dpop_jkt: access_dpop_jkt,
            session_id: grant.session_id,
            nonce: grant.nonce,
            auth_time: grant.auth_time,
            mfa_verified: grant.mfa_verified,
            claims: grant.claims,
            authorization_details,
        },
        refresh_token,
        "authorization_code",
    )
    .await
}

async fn exchange_refresh_token_grant(
    issuer_id: &str,
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    client: &crate::configuration::Client,
    form: &TokenForm,
    database: &Database,
    dpop: Option<&tokens::VerifiedDpopProof>,
) -> HttpResponse {
    if !client
        .grant_types
        .iter()
        .any(|grant| grant == "refresh_token")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client does not allow refresh_token",
        );
    }
    let Some(refresh_token) = form.refresh_token.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };
    if refresh_token.is_empty() || refresh_token.len() > 4_096 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is invalid",
        );
    }
    let requested_scopes = match form.scope.as_deref() {
        Some(scope) if scope.len() <= 2_048 => {
            let scopes = normalized_scopes(scope);
            if !scopes.iter().any(|scope| scope == "openid") {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "a refreshed OpenID grant must retain openid",
                );
            }
            Some(scopes)
        }
        Some(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "requested scope is invalid",
            );
        }
        None => None,
    };
    let requested_authorization_details = match token_authorization_details(form, snapshot, client)
    {
        Ok(details) => details,
        Err(response) => return response,
    };
    let rotation = match database
        .rotate_refresh_token(
            refresh_token,
            issuer.url.trim_end_matches('/'),
            &client.id,
            RefreshTokenSelection {
                scopes: requested_scopes.as_deref(),
                resource: form.resource.as_deref(),
                authorization_details: requested_authorization_details.as_ref(),
                dpop_jkt: (client.client_type == "public")
                    .then(|| dpop.map(|proof| proof.jkt.as_str()))
                    .flatten(),
            },
        )
        .await
    {
        Ok(rotation) => rotation,
        Err(error) => {
            tracing::error!(%error, "failed to rotate refresh token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token storage failed",
            );
        }
    };
    let (rotated_token, mut grant) = match rotation {
        RefreshRotation::Rotated { token, grant } => (token, *grant),
        RefreshRotation::InvalidScope => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "requested scope exceeds the original grant",
            );
        }
        RefreshRotation::InvalidTarget => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "the requested resource does not match the refresh grant",
            );
        }
        RefreshRotation::InvalidAuthorizationDetails => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_authorization_details",
                "requested authorization_details exceeds the refresh grant",
            );
        }
        RefreshRotation::InvalidDpopProof => {
            return invalid_dpop_proof_response("the DPoP proof does not match the refresh token");
        }
        RefreshRotation::Replayed => {
            tracing::warn!(
                event = "refresh_token_replay",
                outcome = "family_revoked",
                issuer_id,
                client_id = %client.id,
                "refresh token replay detected"
            );
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token is invalid",
            );
        }
        RefreshRotation::Invalid => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh token is invalid",
            );
        }
    };
    let currently_valid = snapshot
        .user_for_issuer(&issuer.id, &grant.subject)
        .is_some()
        && grant
            .resource
            .as_ref()
            .is_none_or(|resource| client.resources.contains(resource))
        && grant
            .scopes
            .iter()
            .all(|scope| issuer.scopes.contains(scope) && client.scopes.contains(scope))
        && authorization_details_currently_allowed(snapshot, client, &grant.authorization_details);
    if !currently_valid {
        let _ = database
            .revoke_refresh_token(&rotated_token, &grant.issuer, &grant.client_id)
            .await;
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token grant is no longer active",
        );
    }
    grant.claims = refresh_claims(snapshot, &grant.scopes, grant.claims);
    issue_token_response(
        issuer_id,
        snapshot,
        issuer,
        database,
        TokenIssue {
            issuer: grant.issuer,
            subject: grant.subject,
            client_id: grant.client_id,
            scopes: grant.scopes,
            resource: grant.resource,
            dpop_jkt: dpop.map(|proof| proof.jkt.clone()),
            session_id: grant.session_id,
            nonce: None,
            auth_time: grant.auth_time,
            mfa_verified: grant.mfa_verified,
            claims: grant.claims,
            authorization_details: grant.authorization_details,
        },
        Some(rotated_token),
        "refresh_token",
    )
    .await
}

async fn exchange_client_credentials_grant(
    issuer_id: &str,
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    client: &crate::configuration::Client,
    form: &TokenForm,
    database: &Database,
    dpop: Option<&tokens::VerifiedDpopProof>,
) -> HttpResponse {
    if client.client_type != "confidential"
        || !client
            .grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client does not allow client_credentials",
        );
    }
    if form
        .resource
        .as_ref()
        .is_some_and(|resource| resource.len() > 4_096 || !client.resources.contains(resource))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "the requested resource is not registered for this client",
        );
    }
    let authorization_details = match token_authorization_details(form, snapshot, client) {
        Ok(Some(details)) => details,
        Ok(None) => Value::Array(vec![]),
        Err(response) => return response,
    };
    let eligible = |scope: &&String| {
        issuer.scopes.contains(*scope) && service_scope_allowed(snapshot, scope.as_str())
    };
    let allowed_scopes = client
        .scopes
        .iter()
        .filter(eligible)
        .cloned()
        .collect::<Vec<_>>();
    let scopes = match form.scope.as_deref() {
        Some(scope) if scope.len() <= 2_048 => {
            let requested = normalized_scopes(scope);
            if requested.is_empty()
                || requested
                    .iter()
                    .any(|scope| !allowed_scopes.contains(scope))
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "one or more requested service scopes are not allowed",
                );
            }
            requested
        }
        Some(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "requested scope is invalid",
            );
        }
        None if !allowed_scopes.is_empty() => allowed_scopes,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "the client has no service scope for this issuer",
            );
        }
    };
    let access_grant = AccessGrant {
        issuer: issuer.url.trim_end_matches('/').to_owned(),
        subject: client.id.clone(),
        client_id: client.id.clone(),
        scopes: scopes.clone(),
        grant_type: "client_credentials".to_owned(),
        resource: form.resource.clone(),
        dpop_jkt: dpop.map(|proof| proof.jkt.clone()),
        auth_time: None,
        mfa_verified: false,
        claims: json!({}),
        authorization_details: authorization_details.clone(),
        actor: None,
        expires_at: Utc::now() + Duration::seconds(issuer.token_policy.access_token_lifetime),
    };
    match issue_access_credential(snapshot, issuer, database, &access_grant).await {
        Ok((access_token, _key)) => {
            tracing::info!(
                event = token_audit_event(TokenGrant::ClientCredentials),
                outcome = "success",
                issuer_id,
                client_id = %client.id,
                grant_type = "client_credentials",
                "service access token issued"
            );
            let mut body = json!({
                "access_token": access_token,
                "token_type": if dpop.is_some() { "DPoP" } else { "Bearer" },
                "expires_in": issuer.token_policy.access_token_lifetime,
                "scope": scopes.join(" ")
            });
            if let Some(resource) = &form.resource
                && let Some(body) = body.as_object_mut()
            {
                body.insert("resource".to_owned(), json!(resource));
            }
            insert_authorization_details(&mut body, &authorization_details);
            no_store_json_response(StatusCode::OK, body)
        }
        Err(error) => {
            tracing::error!(?error, "failed to issue service access token");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token storage failed",
            )
        }
    }
}

async fn exchange_access_token_grant(
    issuer_id: &str,
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    client: &crate::configuration::Client,
    form: &TokenForm,
    database: &Database,
    dpop: Option<&tokens::VerifiedDpopProof>,
) -> HttpResponse {
    if client.client_type != "confidential"
        || !client
            .grant_types
            .iter()
            .any(|grant| grant == TOKEN_EXCHANGE_GRANT)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "the client does not allow token exchange",
        );
    }
    let actor_token = match (
        form.actor_token.as_deref(),
        form.actor_token_type.as_deref(),
    ) {
        (None, None) => None,
        (Some(actor_token), Some(ACCESS_TOKEN_TYPE)) if client.actor_token_exchange_allowed => {
            Some(actor_token)
        }
        (Some(_), Some(ACCESS_TOKEN_TYPE)) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "actor token exchange is not allowed for this client",
            );
        }
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "actor_token and its supported actor_token_type must be supplied together",
            );
        }
    };
    if form.subject_token_type.as_deref() != Some(ACCESS_TOKEN_TYPE)
        || form
            .requested_token_type
            .as_deref()
            .is_some_and(|token_type| token_type != ACCESS_TOKEN_TYPE)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "only access tokens can be exchanged and issued",
        );
    }
    let Some(subject_token) = form.subject_token.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject_token is required",
        );
    };
    if subject_token.is_empty()
        || subject_token.len() > MAX_ACCESS_TOKEN_BYTES
        || actor_token.is_some_and(|token| {
            token.is_empty() || token.len() > MAX_ACCESS_TOKEN_BYTES || token == subject_token
        })
        || form
            .subject_token_type
            .as_deref()
            .is_some_and(|value| value.len() > 256)
        || form
            .requested_token_type
            .as_deref()
            .is_some_and(|value| value.len() > 256)
        || form
            .actor_token_type
            .as_deref()
            .is_some_and(|value| value.len() > 256)
        || form
            .audience
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 4_096)
        || form
            .resource
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 4_096)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token exchange parameters are invalid",
        );
    }
    let requested_authorization_details = match token_authorization_details(form, snapshot, client)
    {
        Ok(details) => details,
        Err(response) => return response,
    };

    let subject = match database.access_grant(subject_token).await {
        Ok(Some(grant)) => grant,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "subject token is invalid",
            );
        }
        Err(error) => {
            tracing::error!(%error, "failed to load token exchange subject");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token storage failed",
            );
        }
    };
    if !active_token_exchange_subject(snapshot, issuer, client, &subject) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject token is invalid",
        );
    }
    let delegated_from_client = (subject.client_id != client.id).then(|| subject.client_id.clone());
    if delegated_from_client.is_some() && actor_token.is_none() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "an actor token is required for cross-client delegation",
        );
    }
    if subject
        .dpop_jkt
        .as_deref()
        .is_some_and(|jkt| dpop.is_none_or(|proof| proof.jkt != jkt))
    {
        return invalid_dpop_proof_response("the DPoP proof does not match the subject token");
    }

    let actor = if let Some(actor_token) = actor_token {
        let actor = match database.access_grant(actor_token).await {
            Ok(Some(grant)) => grant,
            Ok(None) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "actor token is invalid",
                );
            }
            Err(error) => {
                tracing::error!(%error, "failed to load token exchange actor");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "token storage failed",
                );
            }
        };
        if !active_token_exchange_actor(snapshot, issuer, client, &actor) {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "actor token is invalid",
            );
        }
        if actor
            .dpop_jkt
            .as_deref()
            .is_some_and(|jkt| dpop.is_none_or(|proof| proof.jkt != jkt))
        {
            return invalid_dpop_proof_response("the DPoP proof does not match the actor token");
        }
        Some(actor)
    } else {
        None
    };

    let authorization_details = match requested_authorization_details {
        Some(requested)
            if !authorization_details_subset(&requested, &subject.authorization_details) =>
        {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_authorization_details",
                "requested authorization_details exceeds the subject token grant",
            );
        }
        Some(requested) => requested,
        None if authorization_details_currently_allowed(
            snapshot,
            client,
            &subject.authorization_details,
        ) =>
        {
            subject.authorization_details.clone()
        }
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_authorization_details",
                "subject token authorization_details are not allowed for the exchanging client",
            );
        }
    };

    let target = match (form.resource.as_deref(), form.audience.as_deref()) {
        (Some(resource), Some(audience)) if resource != audience => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "resource and audience must identify the same registered target",
            );
        }
        (Some(resource), _) | (_, Some(resource)) => Some(resource.to_owned()),
        (None, None) => subject.resource.clone(),
    };
    if target
        .as_ref()
        .is_some_and(|resource| !client.resources.contains(resource))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "the requested target is not registered for this client",
        );
    }

    let scopes = match form.scope.as_deref() {
        Some(scope) if scope.len() <= 2_048 => {
            let requested = normalized_scopes(scope);
            if requested.is_empty()
                || requested.iter().any(|scope| {
                    scope == "offline_access"
                        || !subject.scopes.contains(scope)
                        || !issuer.scopes.contains(scope)
                        || !client.scopes.contains(scope)
                })
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "requested scopes exceed the subject token grant",
                );
            }
            requested
        }
        Some(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "requested scope is invalid",
            );
        }
        None => subject
            .scopes
            .iter()
            .filter(|scope| scope.as_str() != "offline_access")
            .cloned()
            .collect(),
    };
    if scopes.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "the subject token has no exchangeable scope",
        );
    }

    let now = Utc::now();
    let input_expires_at = actor.as_ref().map_or(subject.expires_at, |actor| {
        subject.expires_at.min(actor.expires_at)
    });
    let expires_in = (input_expires_at - now)
        .num_seconds()
        .min(issuer.token_policy.access_token_lifetime);
    if expires_in <= 0 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject token is invalid",
        );
    }
    let dpop_jkt = subject
        .dpop_jkt
        .clone()
        .or_else(|| dpop.map(|proof| proof.jkt.clone()));
    let actor_claim = match actor {
        Some(actor) => match delegated_actor_claim(&actor.subject, subject.actor.as_ref()) {
            Some(actor_claim) => Some(actor_claim),
            None => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "the actor delegation chain is too deep",
                );
            }
        },
        None => subject.actor.clone(),
    };
    let exchanged_grant = AccessGrant {
        issuer: subject.issuer,
        subject: subject.subject,
        client_id: client.id.clone(),
        scopes: scopes.clone(),
        grant_type: TOKEN_EXCHANGE_GRANT.to_owned(),
        resource: target.clone(),
        dpop_jkt: dpop_jkt.clone(),
        auth_time: subject.auth_time,
        mfa_verified: subject.mfa_verified,
        claims: subject.claims,
        authorization_details: authorization_details.clone(),
        actor: actor_claim,
        expires_at: now + Duration::seconds(expires_in),
    };
    match issue_access_credential(snapshot, issuer, database, &exchanged_grant).await {
        Ok((access_token, _key)) => {
            tracing::info!(
                event = token_audit_event(TokenGrant::TokenExchange),
                outcome = "success",
                issuer_id,
                client_id = %client.id,
                grant_type = TOKEN_EXCHANGE_GRANT,
                subject_id = %exchanged_grant.subject,
                delegated = delegated_from_client.is_some(),
                "access token exchanged"
            );
            let mut body = json!({
                "access_token": access_token,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": if dpop_jkt.is_some() { "DPoP" } else { "Bearer" },
                "expires_in": expires_in,
                "scope": scopes.join(" ")
            });
            if let Some(resource) = target
                && let Some(body) = body.as_object_mut()
            {
                body.insert("resource".to_owned(), json!(resource));
            }
            insert_authorization_details(&mut body, &authorization_details);
            no_store_json_response(StatusCode::OK, body)
        }
        Err(error) => {
            tracing::error!(?error, "failed to persist exchanged access token");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token storage failed",
            )
        }
    }
}

fn refresh_claims(
    snapshot: &crate::configuration::Snapshot,
    scopes: &[String],
    claims: Value,
) -> Value {
    let Value::Object(mut claims) = claims else {
        return json!({});
    };
    claims.retain(|claim, _| {
        snapshot
            .configuration
            .claims
            .get(claim)
            .is_some_and(|mapping| scopes.contains(&mapping.scope))
    });
    Value::Object(claims)
}

#[derive(Debug, thiserror::Error)]
enum AccessTokenIssuanceError {
    #[error("signing key unavailable: {0}")]
    Key(sqlx::Error),
    #[error("access token signing failed: {0}")]
    Signing(jsonwebtoken::errors::Error),
    #[error("access token storage failed: {0}")]
    Storage(sqlx::Error),
    #[error("signed access token exceeds the configured transport bound")]
    TooLarge,
    #[error(transparent)]
    Pairwise(#[from] crate::pairwise::PairwiseSubjectError),
}

async fn active_signing_key(
    issuer: &crate::configuration::Issuer,
    database: &Database,
    issuer_url: &str,
) -> Result<SigningKey, sqlx::Error> {
    match issuer.token_policy.signing_key_rotation_interval {
        Some(interval) => database
            .rotate_signing_key_if_due(
                issuer_url,
                interval,
                issuer.signing_key_retention_seconds(),
                Utc::now(),
            )
            .await
            .map(|(key, _changed)| key),
        None => database.signing_key(issuer_url).await,
    }
}

async fn issue_access_credential(
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    database: &Database,
    grant: &AccessGrant,
) -> Result<(String, Option<SigningKey>), AccessTokenIssuanceError> {
    if issuer.token_policy.access_token_format == "opaque" {
        return database
            .issue_access_token(grant)
            .await
            .map(|token| (token, None))
            .map_err(AccessTokenIssuanceError::Storage);
    }

    let key = active_signing_key(issuer, database, &grant.issuer)
        .await
        .map_err(AccessTokenIssuanceError::Key)?;
    let now = Utc::now().timestamp();
    let lifetime = (grant.expires_at.timestamp() - now).max(1);
    let scope = grant.scopes.join(" ");
    let claims = grant.claims.as_object().cloned().unwrap_or_default();
    let client = snapshot
        .client_for_issuer(&issuer.id, &grant.client_id)
        .expect("token grant references a configured client");
    let external_subject =
        crate::pairwise::external_subject(snapshot, &grant.issuer, client, &grant.subject)?;
    let token = tokens::issue_access_token(
        &key,
        &tokens::AccessTokenInput {
            issuer: &grant.issuer,
            subject: &external_subject,
            audience: grant.resource.as_deref().unwrap_or(&grant.client_id),
            client_id: &grant.client_id,
            scope: &scope,
            jti: &random_token(),
            auth_time: grant.auth_time,
            mfa_verified: grant.mfa_verified,
            dpop_jkt: grant.dpop_jkt.as_deref(),
            authorization_details: &grant.authorization_details,
            actor: grant.actor.as_ref(),
            claims: &claims,
            now,
            lifetime,
        },
    )
    .map_err(AccessTokenIssuanceError::Signing)?;
    if token.len() > MAX_ACCESS_TOKEN_BYTES {
        return Err(AccessTokenIssuanceError::TooLarge);
    }
    database
        .store_access_token(&token, grant)
        .await
        .map_err(AccessTokenIssuanceError::Storage)?;
    Ok((token, Some(key)))
}

async fn issue_token_response(
    issuer_id: &str,
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    database: &Database,
    grant: TokenIssue,
    refresh_token: Option<String>,
    grant_type: &'static str,
) -> HttpResponse {
    let claims = grant.claims.as_object().cloned().unwrap_or_default();
    let now = Utc::now().timestamp();
    let access_grant = AccessGrant {
        issuer: grant.issuer.clone(),
        subject: grant.subject.clone(),
        client_id: grant.client_id.clone(),
        scopes: grant.scopes.clone(),
        grant_type: grant_type.to_owned(),
        resource: grant.resource.clone(),
        dpop_jkt: grant.dpop_jkt.clone(),
        auth_time: grant.auth_time,
        mfa_verified: grant.mfa_verified,
        claims: grant.claims.clone(),
        authorization_details: grant.authorization_details.clone(),
        actor: None,
        expires_at: Utc::now() + Duration::seconds(issuer.token_policy.access_token_lifetime),
    };
    let (access_token, access_token_key) =
        match issue_access_credential(snapshot, issuer, database, &access_grant).await {
            Ok(result) => result,
            Err(error) => {
                revoke_unissued_refresh_token(database, refresh_token.as_deref(), &grant).await;
                tracing::error!(?error, "failed to issue access token");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "token storage failed",
                );
            }
        };
    let key_result = match access_token_key {
        Some(key) => Ok(key),
        None => active_signing_key(issuer, database, &grant.issuer).await,
    };
    let key = match key_result {
        Ok(key) => key,
        Err(error) => {
            let _ = database
                .revoke_access_token(&access_token, &access_grant.issuer, &access_grant.client_id)
                .await;
            revoke_unissued_refresh_token(database, refresh_token.as_deref(), &grant).await;
            tracing::error!(%error, "failed to load signing key");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "signing key unavailable",
            );
        }
    };
    let at_hash = tokens::access_token_hash(&access_token);
    let client = snapshot
        .client_for_issuer(issuer_id, &grant.client_id)
        .expect("token grant references a configured client");
    let external_subject =
        match crate::pairwise::external_subject(snapshot, &grant.issuer, client, &grant.subject) {
            Ok(subject) => subject,
            Err(error) => {
                let _ = database
                    .revoke_access_token(
                        &access_token,
                        &access_grant.issuer,
                        &access_grant.client_id,
                    )
                    .await;
                revoke_unissued_refresh_token(database, refresh_token.as_deref(), &grant).await;
                tracing::error!(%error, "failed to derive pairwise subject");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "subject identifier generation unavailable",
                );
            }
        };
    let id_token = match tokens::issue_id_token(
        &key,
        &tokens::IdTokenInput {
            issuer: &grant.issuer,
            subject: &external_subject,
            audience: &grant.client_id,
            session_id: grant.session_id.as_deref(),
            nonce: grant.nonce.as_deref(),
            auth_time: grant.auth_time,
            mfa_verified: grant.mfa_verified,
            at_hash: Some(&at_hash),
            claims: &claims,
            now,
            lifetime: issuer.token_policy.id_token_lifetime,
        },
    ) {
        Ok(token) => token,
        Err(error) => {
            let _ = database
                .revoke_access_token(&access_token, &access_grant.issuer, &access_grant.client_id)
                .await;
            revoke_unissued_refresh_token(database, refresh_token.as_deref(), &grant).await;
            tracing::error!(%error, "failed to sign ID token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token signing failed",
            );
        }
    };
    let mut body = json!({
        "access_token": access_token,
        "token_type": if grant.dpop_jkt.is_some() { "DPoP" } else { "Bearer" },
        "expires_in": issuer.token_policy.access_token_lifetime,
        "scope": grant.scopes.join(" "),
        "id_token": id_token
    });
    if let Some(refresh_token) = refresh_token
        && let Some(body) = body.as_object_mut()
    {
        body.insert("refresh_token".to_owned(), json!(refresh_token));
    }
    if let Some(resource) = &grant.resource
        && let Some(body) = body.as_object_mut()
    {
        body.insert("resource".to_owned(), json!(resource));
    }
    insert_authorization_details(&mut body, &grant.authorization_details);
    tracing::info!(
        event = token_audit_event(TokenGrant::from_grant_type(grant_type)),
        outcome = "success",
        issuer_id,
        client_id = %access_grant.client_id,
        grant_type,
        subject_id = %access_grant.subject
    );
    no_store_json_response(StatusCode::OK, body)
}

async fn revoke_unissued_refresh_token(
    database: &Database,
    refresh_token: Option<&str>,
    grant: &TokenIssue,
) {
    let Some(refresh_token) = refresh_token else {
        return;
    };
    if let Err(error) = database
        .revoke_refresh_token(refresh_token, &grant.issuer, &grant.client_id)
        .await
    {
        tracing::error!(%error, "failed to revoke an unissued refresh family");
    }
}

async fn introspect_token(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<TokenStatusForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let jwt_response_requested = accepts_token_introspection_jwt(&request);
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "unknown issuer");
    };
    let form = form.into_inner();
    if form.token.is_empty() || form.token.len() > MAX_ACCESS_TOKEN_BYTES {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token must be a non-empty bounded value",
        );
    }
    let client = match authenticated_endpoint_client(
        &snapshot,
        &request,
        application.database(),
        issuer,
        EndpointClientAuthentication {
            form_id: form.client_id.as_deref(),
            form_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
            realm: "introspection",
            endpoint_path: "/introspect",
        },
    )
    .await
    {
        Ok(client) if client.client_type == "confidential" && client.introspection_allowed => {
            client
        }
        _ => return invalid_client_response_for("introspection"),
    };
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let issuer_url = issuer.url.trim_end_matches('/');
    let grant = match database.introspection_grant(&form.token, issuer_url).await {
        Ok(grant) => grant,
        Err(error) => {
            tracing::error!(%error, "failed to introspect access token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token storage failed",
            );
        }
    };
    let grant = grant.filter(|grant| {
        active_introspection_grant(&snapshot, issuer, grant)
            && introspection_grant_visible_to_client(client, grant)
    });
    let external_subject = match grant.as_ref() {
        Some(grant) => {
            let token_client = snapshot
                .client_for_issuer(&issuer.id, &grant.client_id)
                .expect("active introspection grant references a configured client");
            match crate::pairwise::external_subject(
                &snapshot,
                &grant.issuer,
                token_client,
                &grant.subject,
            ) {
                Ok(subject) => Some(subject),
                Err(error) => {
                    tracing::error!(%error, "failed to derive introspection subject");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "subject identifier generation unavailable",
                    );
                }
            }
        }
        None => None,
    };
    let response = grant.map_or_else(
        || json!({"active": false}),
        |grant| {
            let mut response = json!({
                "active": true,
                "scope": grant.scopes.join(" "),
                "client_id": grant.client_id,
                "token_type": if grant.dpop_jkt.is_some() { "DPoP" } else { "Bearer" },
                "exp": grant.expires_at.timestamp(),
                "iat": grant.issued_at.timestamp(),
                "sub": external_subject.expect("active grant has an external subject"),
                "iss": grant.issuer
            });
            if let Some(resource) = grant.resource
                && let Some(response) = response.as_object_mut()
            {
                response.insert("aud".to_owned(), json!(resource));
            }
            if let Some(jkt) = grant.dpop_jkt
                && let Some(response) = response.as_object_mut()
            {
                response.insert("cnf".to_owned(), json!({"jkt": jkt}));
            }
            if let Some(auth_time) = grant.auth_time
                && let Some(response) = response.as_object_mut()
            {
                response.insert("auth_time".to_owned(), json!(auth_time));
                response.insert(
                    "acr".to_owned(),
                    json!(if grant.mfa_verified {
                        tokens::MFA_ACR
                    } else {
                        tokens::PASSWORD_ACR
                    }),
                );
                response.insert(
                    "amr".to_owned(),
                    if grant.mfa_verified {
                        json!(["pwd", "otp"])
                    } else {
                        json!(["pwd"])
                    },
                );
            }
            if let Some(actor) = grant.actor
                && let Some(response) = response.as_object_mut()
            {
                response.insert("act".to_owned(), actor);
            }
            insert_authorization_details(&mut response, &grant.authorization_details);
            response
        },
    );
    let token_type_hint = match form.token_type_hint.as_deref() {
        Some("access_token") => "access_token",
        Some(_) => "other",
        None => "unspecified",
    };
    tracing::info!(
        event = "token_introspection",
        outcome = if response["active"] == true { "active" } else { "inactive" },
        issuer_id,
        client_id = %client.id,
        response_format = if jwt_response_requested { "jwt" } else { "json" },
        token_type_hint,
        "access token introspected"
    );
    if jwt_response_requested {
        let key = match active_signing_key(issuer, database, issuer_url).await {
            Ok(key) => key,
            Err(error) => {
                tracing::error!(%error, "failed to load introspection response signing key");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "introspection response signing unavailable",
                );
            }
        };
        let signed = match tokens::issue_token_introspection_response(
            &key,
            &tokens::TokenIntrospectionResponseInput {
                issuer: issuer_url,
                audience: &client.id,
                token_introspection: &response,
                now: Utc::now().timestamp(),
            },
        ) {
            Ok(signed) if signed.len() <= MAX_ACCESS_TOKEN_BYTES => signed,
            Ok(_) => {
                tracing::error!("signed introspection response exceeded the transport bound");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "introspection response is too large",
                );
            }
            Err(error) => {
                tracing::error!(%error, "failed to sign introspection response");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "introspection response signing failed",
                );
            }
        };
        return no_store_token_introspection_jwt_response(signed);
    }
    no_store_json_response(StatusCode::OK, response)
}

async fn revoke_token(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<TokenStatusForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.as_str().to_owned();
    let cors_snapshot = application.snapshot();
    let cors_request = request.clone();
    let cors_client_id = form.client_id.clone();
    let mut response = revoke_token_inner(path, request, form, application).await;
    add_revocation_cors(
        &mut response,
        &cors_request,
        &cors_snapshot,
        &issuer_id,
        cors_client_id.as_deref(),
    );
    response
}

async fn revoke_token_inner(
    path: web::Path<String>,
    request: HttpRequest,
    form: web::Form<TokenStatusForm>,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "unknown issuer");
    };
    let form = form.into_inner();
    if form.token.is_empty() || form.token.len() > MAX_ACCESS_TOKEN_BYTES {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token must be a non-empty bounded value",
        );
    }
    let client = match authenticated_endpoint_client(
        &snapshot,
        &request,
        application.database(),
        issuer,
        EndpointClientAuthentication {
            form_id: form.client_id.as_deref(),
            form_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
            realm: "revocation",
            endpoint_path: "/revoke",
        },
    )
    .await
    {
        Ok(client) => client,
        Err(response) => return response,
    };
    let Some(database) = application.database() else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "database unavailable",
        );
    };
    let access_revoked = match database
        .revoke_access_token(&form.token, issuer.url.trim_end_matches('/'), &client.id)
        .await
    {
        Ok(revoked) => revoked,
        Err(error) => {
            tracing::error!(%error, "failed to revoke access token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token storage failed",
            );
        }
    };
    let refresh_revoked = match database
        .revoke_refresh_token(&form.token, issuer.url.trim_end_matches('/'), &client.id)
        .await
    {
        Ok(revoked) => revoked,
        Err(error) => {
            tracing::error!(%error, "failed to revoke refresh token");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "token storage failed",
            );
        }
    };
    let token_type_hint = match form.token_type_hint.as_deref() {
        Some("access_token") => "access_token",
        Some("refresh_token") => "refresh_token",
        Some(_) => "other",
        None => "unspecified",
    };
    tracing::info!(
        event = "token_revocation",
        outcome = "success",
        issuer_id,
        client_id = %client.id,
        token_type_hint,
        token_found = access_revoked || refresh_revoked,
        "token revocation completed"
    );
    let mut response = HttpResponse::Ok().finish();
    prevent_caching(&mut response);
    response
}

async fn jwks(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> impl Responder {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    let Some(issuer) = snapshot.issuer(&issuer_id) else {
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
        Ok(keys) => cacheable_json_response(
            &request,
            json!({"keys": keys.into_iter().map(|key| json!({
                "kty": "RSA", "kid": key.kid, "use": "sig", "alg": "RS256",
                "n": key.modulus, "e": key.exponent
                })).collect::<Vec<_>>() }),
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

async fn user_info(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> HttpResponse {
    let metrics_application = application.clone();
    let response = user_info_inner(path, request, application).await;
    metrics_application
        .metrics()
        .userinfo(response.status().is_success());
    response
}

async fn user_info_inner(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    let resource_metadata = snapshot
        .issuer(&issuer_id)
        .map(user_info_resource_metadata_url);
    let credential = access_token_credential(&request);
    let (Some((scheme, token)), Some(database)) = (credential, application.database()) else {
        let mut response = invalid_bearer_response(resource_metadata.as_deref());
        add_user_info_cors(&mut response, &request, &snapshot, &issuer_id, None);
        return response;
    };
    let grant = match database.access_grant(token).await {
        Ok(Some(grant)) if valid_user_info_grant(&snapshot, &issuer_id, &grant) => grant,
        _ => {
            tracing::warn!(
                event = "userinfo",
                outcome = "failure",
                issuer_id,
                reason = "invalid_token",
                "UserInfo request rejected"
            );
            let mut response = if scheme.eq_ignore_ascii_case("dpop") {
                invalid_dpop_access_response("invalid_token", "the access token is invalid")
            } else {
                invalid_bearer_response(resource_metadata.as_deref())
            };
            if scheme.eq_ignore_ascii_case("dpop") {
                add_resource_metadata_to_challenge(&mut response, resource_metadata.as_deref());
            }
            add_user_info_cors(&mut response, &request, &snapshot, &issuer_id, None);
            return response;
        }
    };
    if let Some(expected_jkt) = grant.dpop_jkt.as_deref() {
        if !scheme.eq_ignore_ascii_case("dpop") {
            let mut response = invalid_dpop_access_response(
                "invalid_token",
                "a DPoP-bound access token must use the DPoP authorization scheme",
            );
            add_resource_metadata_to_challenge(&mut response, resource_metadata.as_deref());
            add_user_info_cors(
                &mut response,
                &request,
                &snapshot,
                &issuer_id,
                Some(&grant.client_id),
            );
            return response;
        }
        let issuer = snapshot
            .issuer(&issuer_id)
            .expect("validated UserInfo issuer");
        match verified_dpop_endpoint_proof(
            &request,
            database,
            issuer,
            "/userinfo",
            "userinfo",
            Some(token),
        )
        .await
        {
            Ok(Some(proof)) if proof.jkt == expected_jkt => {
                audit_userinfo_dpop_proof_accepted(&proof);
            }
            Ok(_) | Err(DpopProofError::Invalid) => {
                let mut response = invalid_dpop_access_response(
                    "invalid_dpop_proof",
                    "the DPoP proof is missing, invalid, mismatched, or replayed",
                );
                add_resource_metadata_to_challenge(&mut response, resource_metadata.as_deref());
                add_user_info_cors(
                    &mut response,
                    &request,
                    &snapshot,
                    &issuer_id,
                    Some(&grant.client_id),
                );
                return response;
            }
            Err(DpopProofError::NonceRequired(nonce)) => {
                let mut response = dpop_nonce_response(true, &nonce);
                add_resource_metadata_to_challenge(&mut response, resource_metadata.as_deref());
                add_user_info_cors(
                    &mut response,
                    &request,
                    &snapshot,
                    &issuer_id,
                    Some(&grant.client_id),
                );
                return response;
            }
            Err(DpopProofError::Unavailable) => {
                let mut response = oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "DPoP replay storage unavailable",
                );
                add_user_info_cors(
                    &mut response,
                    &request,
                    &snapshot,
                    &issuer_id,
                    Some(&grant.client_id),
                );
                return response;
            }
        }
    } else if !scheme.eq_ignore_ascii_case("bearer") {
        let mut response = invalid_bearer_response(resource_metadata.as_deref());
        add_user_info_cors(
            &mut response,
            &request,
            &snapshot,
            &issuer_id,
            Some(&grant.client_id),
        );
        return response;
    }

    if let Some(requirement) =
        user_info_step_up_requirement(&snapshot, &issuer_id, &grant, Utc::now().timestamp())
    {
        tracing::warn!(
            event = "userinfo",
            outcome = "failure",
            issuer_id,
            client_id = %grant.client_id,
            subject_id = %grant.subject,
            reason = "insufficient_user_authentication",
            "UserInfo request requires step-up authentication"
        );
        let mut response = insufficient_user_authentication_response(
            scheme,
            &requirement,
            resource_metadata.as_deref(),
        );
        add_user_info_cors(
            &mut response,
            &request,
            &snapshot,
            &issuer_id,
            Some(&grant.client_id),
        );
        return response;
    }

    let client = snapshot
        .client_for_issuer(&issuer_id, &grant.client_id)
        .expect("validated UserInfo client");
    let external_subject =
        match crate::pairwise::external_subject(&snapshot, &grant.issuer, client, &grant.subject) {
            Ok(subject) => subject,
            Err(error) => {
                tracing::error!(%error, "failed to derive UserInfo subject");
                let mut response = oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "subject identifier generation unavailable",
                );
                add_user_info_cors(
                    &mut response,
                    &request,
                    &snapshot,
                    &issuer_id,
                    Some(&grant.client_id),
                );
                return response;
            }
        };
    let mut claims = grant.claims.as_object().cloned().unwrap_or_default();
    claims.insert("sub".to_owned(), json!(external_subject));
    let mut response = if client.userinfo_signed_response_alg.as_deref() == Some("RS256") {
        let issuer = snapshot
            .issuer(&issuer_id)
            .expect("validated UserInfo issuer");
        let key = match active_signing_key(issuer, database, &grant.issuer).await {
            Ok(key) => key,
            Err(error) => {
                tracing::error!(%error, "failed to load the UserInfo signing key");
                let mut response = oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "UserInfo signing is temporarily unavailable",
                );
                add_user_info_cors(
                    &mut response,
                    &request,
                    &snapshot,
                    &issuer_id,
                    Some(&grant.client_id),
                );
                return response;
            }
        };
        let now = Utc::now().timestamp();
        let signed = match tokens::issue_user_info_response(
            &key,
            &tokens::UserInfoResponseInput {
                issuer: &grant.issuer,
                audience: &grant.client_id,
                claims: &claims,
                now,
                lifetime: issuer.token_policy.id_token_lifetime.min(300),
            },
        ) {
            Ok(signed) if signed.len() <= MAX_ACCESS_TOKEN_BYTES => signed,
            Ok(_) => {
                tracing::error!("signed UserInfo response exceeds the transport bound");
                let mut response = oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "UserInfo signing is temporarily unavailable",
                );
                add_user_info_cors(
                    &mut response,
                    &request,
                    &snapshot,
                    &issuer_id,
                    Some(&grant.client_id),
                );
                return response;
            }
            Err(error) => {
                tracing::error!(%error, "failed to sign the UserInfo response");
                let mut response = oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "UserInfo signing is temporarily unavailable",
                );
                add_user_info_cors(
                    &mut response,
                    &request,
                    &snapshot,
                    &issuer_id,
                    Some(&grant.client_id),
                );
                return response;
            }
        };
        HttpResponse::Ok()
            .content_type("application/jwt")
            .body(signed)
    } else {
        json_response(StatusCode::OK, Value::Object(claims))
    };
    prevent_caching(&mut response);
    add_user_info_cors(
        &mut response,
        &request,
        &snapshot,
        &issuer_id,
        Some(&grant.client_id),
    );
    tracing::info!(
        event = "userinfo",
        outcome = "success",
        issuer_id,
        client_id = %grant.client_id,
        subject_id = %grant.subject,
        dpop_bound = grant.dpop_jkt.is_some(),
        response_format = if client.userinfo_signed_response_alg.as_deref() == Some("RS256") {
            "jwt"
        } else {
            "json"
        },
        "UserInfo claims returned"
    );
    response
}

fn audit_userinfo_dpop_proof_accepted(_proof: &tokens::VerifiedDpopProof) {
    tracing::debug!(
        event = "dpop_proof",
        outcome = "accepted",
        endpoint = "userinfo",
        "DPoP-bound UserInfo proof accepted"
    );
}

async fn user_info_options(
    path: web::Path<String>,
    request: HttpRequest,
    application: web::Data<Application>,
) -> HttpResponse {
    let issuer_id = path.into_inner();
    let snapshot = application.snapshot();
    if snapshot.issuer(&issuer_id).is_none() {
        return json_response(StatusCode::NOT_FOUND, json!({"error": "not_found"}));
    }
    let requested_method = request
        .headers()
        .get("access-control-request-method")
        .and_then(|value| value.to_str().ok());
    let requested_headers_supported = request
        .headers()
        .get("access-control-request-headers")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|headers| {
            headers.split(',').all(|header| {
                matches!(
                    header.trim().to_ascii_lowercase().as_str(),
                    "authorization" | "content-type" | "dpop"
                )
            })
        });
    let origin = request
        .headers()
        .get(actix_web::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if !matches!(requested_method, Some("GET" | "POST"))
        || !requested_headers_supported
        || !origin
            .is_some_and(|origin| user_info_origin_allowed(&snapshot, &issuer_id, origin, None))
    {
        return no_store_empty_response(StatusCode::FORBIDDEN);
    }

    let mut response = HttpResponse::NoContent().finish();
    add_user_info_cors(&mut response, &request, &snapshot, &issuer_id, None);
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("access-control-allow-methods"),
        actix_web::http::header::HeaderValue::from_static("GET, POST"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("access-control-allow-headers"),
        actix_web::http::header::HeaderValue::from_static("Authorization, Content-Type, DPoP"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("access-control-max-age"),
        actix_web::http::header::HeaderValue::from_static("600"),
    );
    response
}

fn add_user_info_cors(
    response: &mut HttpResponse,
    request: &HttpRequest,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    client_id: Option<&str>,
) {
    let Some(origin) = request
        .headers()
        .get(actix_web::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|origin| {
            registered_redirect_origin_allowed(snapshot, issuer_id, origin, client_id, false)
        })
    else {
        return;
    };
    let Ok(origin) = actix_web::http::header::HeaderValue::from_str(origin) else {
        return;
    };
    response
        .headers_mut()
        .insert(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response.headers_mut().insert(
        actix_web::http::header::VARY,
        actix_web::http::header::HeaderValue::from_static("Origin"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("cross-origin-resource-policy"),
        actix_web::http::header::HeaderValue::from_static("cross-origin"),
    );
    response.headers_mut().insert(
        actix_web::http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
        actix_web::http::header::HeaderValue::from_static("DPoP-Nonce, WWW-Authenticate"),
    );
}

fn user_info_origin_allowed(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    origin: &str,
    client_id: Option<&str>,
) -> bool {
    registered_redirect_origin_allowed(snapshot, issuer_id, origin, client_id, false)
}

fn add_token_cors(
    response: &mut HttpResponse,
    request: &HttpRequest,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    client_id: Option<&str>,
) {
    let Some(origin) = request
        .headers()
        .get(actix_web::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|origin| token_origin_allowed(snapshot, issuer_id, origin, client_id))
    else {
        return;
    };
    let Ok(origin) = actix_web::http::header::HeaderValue::from_str(origin) else {
        return;
    };
    response
        .headers_mut()
        .insert(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response.headers_mut().insert(
        actix_web::http::header::VARY,
        actix_web::http::header::HeaderValue::from_static("Origin"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("cross-origin-resource-policy"),
        actix_web::http::header::HeaderValue::from_static("cross-origin"),
    );
    response.headers_mut().insert(
        actix_web::http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
        actix_web::http::header::HeaderValue::from_static("DPoP-Nonce"),
    );
}

fn token_origin_allowed(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    origin: &str,
    client_id: Option<&str>,
) -> bool {
    registered_redirect_origin_allowed(snapshot, issuer_id, origin, client_id, true)
}

fn add_revocation_cors(
    response: &mut HttpResponse,
    request: &HttpRequest,
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    client_id: Option<&str>,
) {
    let Some(origin) = request
        .headers()
        .get(actix_web::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|origin| revocation_origin_allowed(snapshot, issuer_id, origin, client_id))
    else {
        return;
    };
    let Ok(origin) = actix_web::http::header::HeaderValue::from_str(origin) else {
        return;
    };
    response
        .headers_mut()
        .insert(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response.headers_mut().insert(
        actix_web::http::header::VARY,
        actix_web::http::header::HeaderValue::from_static("Origin"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("cross-origin-resource-policy"),
        actix_web::http::header::HeaderValue::from_static("cross-origin"),
    );
    response.headers_mut().insert(
        actix_web::http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
        actix_web::http::header::HeaderValue::from_static("WWW-Authenticate"),
    );
}

fn revocation_origin_allowed(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    origin: &str,
    client_id: Option<&str>,
) -> bool {
    registered_redirect_origin_allowed(snapshot, issuer_id, origin, client_id, true)
}

pub fn public_client_cors_origin_allowed(
    snapshot: &crate::configuration::Snapshot,
    path: &str,
    origin: &str,
) -> bool {
    let Some(path) = path.strip_prefix('/').filter(|path| !path.starts_with('/')) else {
        return false;
    };
    let mut segments = path.split('/');
    let Some(issuer_id) = segments.next().filter(|segment| !segment.is_empty()) else {
        return false;
    };
    let Some(endpoint) = segments.next() else {
        return false;
    };
    if segments.next().is_some() || !matches!(endpoint, "token" | "par" | "revoke") {
        return false;
    }
    registered_redirect_origin_allowed(snapshot, issuer_id, origin, None, true)
}

fn registered_redirect_origin_allowed(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    origin: &str,
    client_id: Option<&str>,
    public_clients_only: bool,
) -> bool {
    let Ok(origin_url) = url::Url::parse(origin) else {
        return false;
    };
    if origin_url.path() != "/"
        || origin_url.query().is_some()
        || origin_url.fragment().is_some()
        || origin_url.origin().ascii_serialization() != origin
    {
        return false;
    }
    snapshot
        .active_clients_for_issuer(issuer_id)
        .filter(|client| client_id.is_none_or(|expected| client.id == expected))
        .filter(|client| !public_clients_only || client.client_type == "public")
        .flat_map(|client| client.redirect_uris.iter())
        .filter_map(|redirect| url::Url::parse(redirect).ok())
        .any(|redirect| redirect.origin() == origin_url.origin())
}

fn valid_user_info_grant(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    grant: &AccessGrant,
) -> bool {
    let (Some(issuer), Some(client)) = (
        snapshot.issuer(issuer_id),
        snapshot.client_for_issuer(issuer_id, &grant.client_id),
    ) else {
        return false;
    };
    grant.issuer == issuer.url.trim_end_matches('/')
        && grant.resource.is_none()
        && snapshot
            .user_for_issuer(issuer_id, &grant.subject)
            .is_some()
        && grant.scopes.iter().any(|scope| scope == "openid")
        && grant
            .scopes
            .iter()
            .all(|scope| issuer.scopes.contains(scope) && client.scopes.contains(scope))
        && authorization_details_currently_allowed(snapshot, client, &grant.authorization_details)
        && grant
            .actor
            .as_ref()
            .is_none_or(|actor| actor_chain_depth(actor).is_some())
        && match grant.grant_type.as_str() {
            "authorization_code" => {
                grant.actor.is_none()
                    && client
                        .grant_types
                        .iter()
                        .any(|grant| grant == "authorization_code")
            }
            "refresh_token" => {
                grant.actor.is_none()
                    && client
                        .grant_types
                        .iter()
                        .any(|grant| grant == "refresh_token")
            }
            DEVICE_CODE_GRANT => {
                grant.actor.is_none()
                    && client
                        .grant_types
                        .iter()
                        .any(|grant| grant == DEVICE_CODE_GRANT)
            }
            TOKEN_EXCHANGE_GRANT => {
                grant
                    .actor
                    .as_ref()
                    .is_none_or(|_| client.actor_token_exchange_allowed)
                    && client
                        .grant_types
                        .iter()
                        .any(|grant| grant == TOKEN_EXCHANGE_GRANT)
            }
            _ => false,
        }
}

#[derive(Debug, PartialEq, Eq)]
struct UserInfoStepUpRequirement {
    acr_values: Option<String>,
    max_age: Option<i64>,
}

fn user_info_step_up_requirement(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    grant: &AccessGrant,
    now: i64,
) -> Option<UserInfoStepUpRequirement> {
    let client = snapshot.client_for_issuer(issuer_id, &grant.client_id)?;
    let acr_values = client.required_acr.as_ref().and_then(|required_acr| {
        let satisfied = match required_acr.as_str() {
            crate::configuration::PASSWORD_ACR => grant.auth_time.is_some(),
            crate::configuration::MFA_ACR => grant.auth_time.is_some() && grant.mfa_verified,
            _ => true,
        };
        (!satisfied).then(|| required_acr.clone())
    });
    let max_age = client.max_authentication_age.filter(|max_age| {
        grant
            .auth_time
            .is_none_or(|auth_time| auth_time < now.saturating_sub(*max_age))
    });

    (acr_values.is_some() || max_age.is_some()).then_some(UserInfoStepUpRequirement {
        acr_values,
        max_age,
    })
}

fn actor_chain_depth(actor: &Value) -> Option<usize> {
    let mut current = actor;
    let mut depth = 0;
    loop {
        let object = current.as_object()?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "sub" | "act"))
            || object
                .get("sub")
                .and_then(Value::as_str)
                .is_none_or(|subject| subject.is_empty() || subject.len() > 256)
        {
            return None;
        }
        depth += 1;
        if depth > MAX_ACTOR_CHAIN_DEPTH {
            return None;
        }
        match object.get("act") {
            Some(nested) => current = nested,
            None => return Some(depth),
        }
    }
}

fn delegated_actor_claim(subject: &str, prior: Option<&Value>) -> Option<Value> {
    if subject.is_empty()
        || subject.len() > 256
        || prior.is_some_and(|actor| {
            actor_chain_depth(actor).is_none_or(|depth| depth >= MAX_ACTOR_CHAIN_DEPTH)
        })
    {
        return None;
    }
    let mut actor = serde_json::Map::from_iter([("sub".to_owned(), json!(subject))]);
    if let Some(prior) = prior {
        actor.insert("act".to_owned(), prior.clone());
    }
    Some(Value::Object(actor))
}

fn active_token_exchange_actor(
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    client: &crate::configuration::Client,
    grant: &AccessGrant,
) -> bool {
    client.actor_token_exchange_allowed
        && grant.grant_type == "client_credentials"
        && grant.subject == client.id
        && grant.auth_time.is_none()
        && grant.actor.is_none()
        && active_token_exchange_subject(snapshot, issuer, client, grant)
}

fn active_token_exchange_subject(
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    client: &crate::configuration::Client,
    grant: &AccessGrant,
) -> bool {
    let Some(source_client) = snapshot.client_for_issuer(&issuer.id, &grant.client_id) else {
        return false;
    };
    if grant.issuer != issuer.url.trim_end_matches('/')
        || (source_client.id != client.id
            && !source_client
                .authorized_actor_clients
                .iter()
                .any(|actor| actor == &client.id))
        || grant
            .resource
            .as_ref()
            .is_some_and(|resource| !source_client.resources.contains(resource))
        || grant
            .scopes
            .iter()
            .any(|scope| !issuer.scopes.contains(scope) || !source_client.scopes.contains(scope))
        || !authorization_details_currently_allowed(
            snapshot,
            source_client,
            &grant.authorization_details,
        )
        || grant
            .actor
            .as_ref()
            .is_some_and(|actor| actor_chain_depth(actor).is_none())
    {
        return false;
    }
    match grant.grant_type.as_str() {
        "client_credentials" => {
            grant.actor.is_none()
                && grant.subject == source_client.id
                && source_client
                    .grant_types
                    .iter()
                    .any(|grant| grant == "client_credentials")
                && grant
                    .scopes
                    .iter()
                    .all(|scope| service_scope_allowed(snapshot, scope))
        }
        "authorization_code" | "refresh_token" | DEVICE_CODE_GRANT => {
            grant.actor.is_none()
                && snapshot
                    .user_for_issuer(&issuer.id, &grant.subject)
                    .is_some()
                && source_client.grant_types.iter().any(|configured| {
                    configured == &grant.grant_type
                        || (grant.grant_type == "refresh_token" && configured == "refresh_token")
                })
        }
        TOKEN_EXCHANGE_GRANT => {
            source_client
                .grant_types
                .iter()
                .any(|grant| grant == TOKEN_EXCHANGE_GRANT)
                && grant
                    .actor
                    .as_ref()
                    .is_none_or(|_| source_client.actor_token_exchange_allowed)
                && (snapshot
                    .user_for_issuer(&issuer.id, &grant.subject)
                    .is_some()
                    || (grant.subject == source_client.id
                        && grant
                            .scopes
                            .iter()
                            .all(|scope| service_scope_allowed(snapshot, scope))))
        }
        _ => false,
    }
}

fn active_introspection_grant(
    snapshot: &crate::configuration::Snapshot,
    issuer: &crate::configuration::Issuer,
    grant: &crate::database::IntrospectionGrant,
) -> bool {
    let Some(client) = snapshot.client_for_issuer(&issuer.id, &grant.client_id) else {
        return false;
    };
    if grant.issuer != issuer.url.trim_end_matches('/')
        || grant
            .resource
            .as_ref()
            .is_some_and(|resource| !client.resources.contains(resource))
        || grant
            .scopes
            .iter()
            .any(|scope| !issuer.scopes.contains(scope) || !client.scopes.contains(scope))
        || !authorization_details_currently_allowed(snapshot, client, &grant.authorization_details)
        || grant
            .actor
            .as_ref()
            .is_some_and(|actor| actor_chain_depth(actor).is_none())
    {
        return false;
    }
    match grant.grant_type.as_str() {
        "client_credentials" => {
            client.client_type == "confidential"
                && grant.actor.is_none()
                && grant.subject == client.id
                && client
                    .grant_types
                    .iter()
                    .any(|grant| grant == "client_credentials")
                && grant
                    .scopes
                    .iter()
                    .all(|scope| service_scope_allowed(snapshot, scope))
        }
        "authorization_code" | "refresh_token" | DEVICE_CODE_GRANT => {
            grant.actor.is_none()
                && snapshot
                    .user_for_issuer(&issuer.id, &grant.subject)
                    .is_some()
                && client
                    .grant_types
                    .iter()
                    .any(|configured| configured == &grant.grant_type)
        }
        TOKEN_EXCHANGE_GRANT => {
            client
                .grant_types
                .iter()
                .any(|grant| grant == TOKEN_EXCHANGE_GRANT)
                && grant
                    .actor
                    .as_ref()
                    .is_none_or(|_| client.actor_token_exchange_allowed)
                && (snapshot
                    .user_for_issuer(&issuer.id, &grant.subject)
                    .is_some()
                    || (grant.subject == client.id
                        && grant
                            .scopes
                            .iter()
                            .all(|scope| service_scope_allowed(snapshot, scope))))
        }
        _ => false,
    }
}

fn introspection_grant_visible_to_client(
    client: &crate::configuration::Client,
    grant: &crate::database::IntrospectionGrant,
) -> bool {
    grant.resource.as_ref().map_or_else(
        || grant.client_id == client.id,
        |resource| client.resources.contains(resource),
    )
}

fn accepts_token_introspection_jwt(request: &HttpRequest) -> bool {
    request
        .headers()
        .get_all(actix_web::http::header::ACCEPT)
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|range| {
            let mut parts = range.trim().split(';');
            let media_type_matches = parts.next().is_some_and(|media_type| {
                media_type.eq_ignore_ascii_case("application/token-introspection+jwt")
            });
            media_type_matches
                && !parts.any(|parameter| {
                    parameter
                        .trim()
                        .split_once('=')
                        .is_some_and(|(name, value)| {
                            name.trim().eq_ignore_ascii_case("q")
                                && value
                                    .trim()
                                    .parse::<f32>()
                                    .is_ok_and(|quality| quality <= 0.0)
                        })
                })
        })
}

fn service_scope_allowed(snapshot: &crate::configuration::Snapshot, scope: &str) -> bool {
    scope != "openid"
        && scope != "offline_access"
        && !snapshot
            .configuration
            .claims
            .values()
            .any(|mapping| mapping.scope == scope)
}

#[derive(Debug)]
enum DpopProofError {
    Invalid,
    NonceRequired(String),
    Unavailable,
}

async fn verified_dpop_endpoint_proof(
    request: &HttpRequest,
    database: &Database,
    issuer: &crate::configuration::Issuer,
    endpoint_path: &str,
    nonce_context: &'static str,
    access_token: Option<&str>,
) -> Result<Option<tokens::VerifiedDpopProof>, DpopProofError> {
    let header_name = actix_web::http::header::HeaderName::from_static("dpop");
    let mut values = request.headers().get_all(header_name);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(DpopProofError::Invalid);
    }
    let proof = value.to_str().map_err(|_| DpopProofError::Invalid)?;
    let clock_skew = u64::try_from(issuer.token_policy.clock_skew).unwrap_or_default();
    let now = Utc::now();
    let endpoint_uri = format!("{}{}", issuer.url.trim_end_matches('/'), endpoint_path);
    let verified = tokens::verify_dpop_proof(
        proof,
        request.method().as_str(),
        &endpoint_uri,
        access_token,
        clock_skew,
        now.timestamp(),
    )
    .map_err(|_| DpopProofError::Invalid)?;
    if issuer.token_policy.dpop_nonce_required {
        match database
            .validate_or_issue_dpop_nonce(
                issuer.url.trim_end_matches('/'),
                nonce_context,
                &verified.jkt,
                verified.nonce.as_deref(),
                issuer.token_policy.dpop_nonce_lifetime,
            )
            .await
        {
            Ok(None) => {}
            Ok(Some(nonce)) => return Err(DpopProofError::NonceRequired(nonce)),
            Err(error) => {
                tracing::error!(%error, "failed to validate DPoP nonce state");
                return Err(DpopProofError::Unavailable);
            }
        }
    }
    let replay_lifetime = i64::try_from(clock_skew)
        .unwrap_or(i64::MAX)
        .saturating_mul(2)
        .saturating_add(300);
    let expires_at = now + Duration::seconds(replay_lifetime);
    match database
        .register_dpop_proof(&verified.jkt, &verified.jti, expires_at)
        .await
    {
        Ok(true) => Ok(Some(verified)),
        Ok(false) => Err(DpopProofError::Invalid),
        Err(error) => {
            tracing::error!(%error, "failed to persist DPoP proof replay state");
            Err(DpopProofError::Unavailable)
        }
    }
}

fn access_token_credential(request: &HttpRequest) -> Option<(&str, &str)> {
    let mut values = request
        .headers()
        .get_all(actix_web::http::header::AUTHORIZATION);
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if token.is_empty() || token.len() > MAX_ACCESS_TOKEN_BYTES || parts.next().is_some() {
        return None;
    }
    Some((scheme, token))
}

#[cfg(test)]
fn bearer_token(request: &HttpRequest) -> Option<&str> {
    access_token_credential(request)
        .and_then(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer").then_some(token))
}

fn basic_credentials(request: &HttpRequest) -> Result<Option<(String, String)>, ()> {
    let mut values = request
        .headers()
        .get_all(actix_web::http::header::AUTHORIZATION);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next().ok_or(())?;
    let encoded = parts.next().ok_or(())?;
    if !scheme.eq_ignore_ascii_case("basic") || parts.next().is_some() {
        return Err(());
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| ())?;
    let decoded = String::from_utf8(decoded).map_err(|_| ())?;
    let (id, secret) = decoded.split_once(':').ok_or(())?;
    let id = decode_form_component(id).ok_or(())?;
    let secret = decode_form_component(secret).ok_or(())?;
    Ok(Some((id, secret)))
}

fn decode_form_component(value: &str) -> Option<String> {
    let encoded = format!("value={value}");
    let mut pairs = url::form_urlencoded::parse(encoded.as_bytes());
    let (key, value) = pairs.next()?;
    (key == "value" && pairs.next().is_none()).then(|| value.into_owned())
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
    let expected = configured_client_secret(client);
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

fn configured_client_secret(client: &crate::configuration::Client) -> Option<Zeroizing<String>> {
    client
        .secret_reference
        .as_ref()
        .and_then(|reference| match reference {
            Value::Object(reference)
                if reference.get("provider").and_then(Value::as_str) == Some("env") =>
            {
                reference
                    .get("key")
                    .and_then(Value::as_str)
                    .and_then(|key| std::env::var(key).ok())
                    .filter(|secret| !secret.is_empty())
                    .map(Zeroizing::new)
            }
            _ => None,
        })
}

async fn authenticated_endpoint_client<'a>(
    snapshot: &'a crate::configuration::Snapshot,
    request: &HttpRequest,
    database: Option<&Database>,
    issuer: &crate::configuration::Issuer,
    authentication: EndpointClientAuthentication<'_>,
) -> Result<&'a crate::configuration::Client, HttpResponse> {
    let EndpointClientAuthentication {
        form_id,
        form_secret,
        client_assertion_type,
        client_assertion,
        realm,
        endpoint_path,
    } = authentication;
    let (basic_id, basic_secret) = match basic_credentials(request) {
        Ok(Some((id, secret))) => (Some(id), Some(secret)),
        Ok(None) => (None, None),
        Err(()) => return Err(invalid_client_response_for(realm)),
    };
    if basic_id.is_some() && form_id.is_some() && basic_id.as_deref() != form_id {
        return Err(invalid_client_response_for(realm));
    }
    let client_id = basic_id.as_deref().or(form_id).unwrap_or_default();
    let Some(client) = snapshot.client_for_issuer(&issuer.id, client_id) else {
        return Err(invalid_client_response_for(realm));
    };
    if matches!(
        client.authentication_method.as_deref(),
        Some("private_key_jwt" | "client_secret_jwt")
    ) {
        let valid_transport = basic_id.is_none()
            && basic_secret.is_none()
            && form_secret.is_none()
            && form_id == Some(client.id.as_str())
            && client_assertion_type
                == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        let Some(assertion) = client_assertion.filter(|_| valid_transport) else {
            return Err(invalid_client_assertion_response());
        };
        let issuer_url = issuer.url.trim_end_matches('/');
        let expected_audience = format!("{issuer_url}{endpoint_path}");
        let clock_skew = u64::try_from(issuer.token_policy.clock_skew).unwrap_or_default();
        let now = Utc::now().timestamp();
        let verified = match client.authentication_method.as_deref() {
            Some("private_key_jwt") => {
                let Some(jwks) = &client.jwks else {
                    return Err(invalid_client_assertion_response());
                };
                crate::tokens::verify_client_assertion(
                    assertion,
                    jwks,
                    &client.id,
                    &expected_audience,
                    clock_skew,
                    now,
                )
            }
            Some("client_secret_jwt") => {
                let secret = configured_client_secret(client)
                    .ok_or_else(invalid_client_assertion_response)?;
                crate::tokens::verify_client_secret_assertion(
                    assertion,
                    &secret,
                    &client.id,
                    &expected_audience,
                    clock_skew,
                    now,
                )
            }
            _ => unreachable!("assertion authentication method matched above"),
        }
        .map_err(|_| invalid_client_assertion_response())?;
        let replay_expires_at = verified
            .expires_at
            .saturating_add(i64::try_from(clock_skew).unwrap_or(i64::MAX));
        let expires_at = DateTime::<Utc>::from_timestamp(replay_expires_at, 0)
            .ok_or_else(invalid_client_assertion_response)?;
        let Some(database) = database else {
            return Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "client authentication storage unavailable",
            ));
        };
        return match database
            .register_client_assertion(issuer_url, &client.id, &verified.jti, expires_at)
            .await
        {
            Ok(true) => Ok(client),
            Ok(false) => {
                tracing::warn!(
                    event = "client_assertion_replay",
                    outcome = "rejected",
                    client_id = %client.id,
                    endpoint = endpoint_path,
                    "client assertion replay rejected"
                );
                Err(invalid_client_assertion_response())
            }
            Err(error) => {
                tracing::error!(%error, "failed to persist client assertion replay state");
                Err(oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "client authentication storage unavailable",
                ))
            }
        };
    }
    if client_assertion_type.is_some() || client_assertion.is_some() {
        return Err(invalid_client_response_for(realm));
    }
    if !authenticate_client(
        client,
        basic_id.as_deref(),
        basic_secret.as_deref(),
        form_id,
        form_secret,
    ) {
        return Err(invalid_client_response_for(realm));
    }
    Ok(client)
}

struct EndpointClientAuthentication<'a> {
    form_id: Option<&'a str>,
    form_secret: Option<&'a str>,
    client_assertion_type: Option<&'a str>,
    client_assertion: Option<&'a str>,
    realm: &'a str,
    endpoint_path: &'a str,
}

fn invalid_client_assertion_response() -> HttpResponse {
    oauth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "client assertion authentication failed",
    )
}

fn invalid_client_response_for(realm: &str) -> HttpResponse {
    let mut response = oauth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "client authentication failed",
    );
    if let Ok(value) =
        actix_web::http::header::HeaderValue::from_str(&format!("Basic realm=\"{realm}\""))
    {
        response
            .headers_mut()
            .insert(actix_web::http::header::WWW_AUTHENTICATE, value);
    }
    response
}

fn invalid_bearer_response(resource_metadata: Option<&str>) -> HttpResponse {
    let mut response = oauth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "bearer token is missing or invalid",
    );
    response.headers_mut().insert(
        actix_web::http::header::WWW_AUTHENTICATE,
        actix_web::http::header::HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    add_resource_metadata_to_challenge(&mut response, resource_metadata);
    response
}

fn insufficient_user_authentication_response(
    authorization_scheme: &str,
    requirement: &UserInfoStepUpRequirement,
    resource_metadata: Option<&str>,
) -> HttpResponse {
    let description = match (
        requirement.acr_values.is_some(),
        requirement.max_age.is_some(),
    ) {
        (true, true) => "a stronger and more recent authentication is required",
        (true, false) => "a stronger authentication is required",
        (false, true) => "a more recent authentication is required",
        (false, false) => "the authentication requirements are not met",
    };
    let scheme = if authorization_scheme.eq_ignore_ascii_case("dpop") {
        "DPoP"
    } else {
        "Bearer"
    };
    let mut challenge = format!(
        "{scheme} error=\"insufficient_user_authentication\", error_description=\"{description}\""
    );
    if scheme == "DPoP" {
        challenge.push_str(", algs=\"EdDSA ES256 RS256\"");
    }
    if let Some(acr_values) = requirement.acr_values.as_deref() {
        challenge.push_str(&format!(", acr_values=\"{acr_values}\""));
    }
    if let Some(max_age) = requirement.max_age {
        challenge.push_str(&format!(", max_age=\"{max_age}\""));
    }
    let mut response = oauth_error(
        StatusCode::UNAUTHORIZED,
        "insufficient_user_authentication",
        description,
    );
    if let Ok(value) = actix_web::http::header::HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(actix_web::http::header::WWW_AUTHENTICATE, value);
    }
    add_resource_metadata_to_challenge(&mut response, resource_metadata);
    response
}

fn add_resource_metadata_to_challenge(
    response: &mut HttpResponse,
    resource_metadata: Option<&str>,
) {
    let Some(resource_metadata) = resource_metadata else {
        return;
    };
    let Some(challenge) = response
        .headers()
        .get(actix_web::http::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let challenge = format!("{challenge}, resource_metadata=\"{resource_metadata}\"");
    if let Ok(challenge) = actix_web::http::header::HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(actix_web::http::header::WWW_AUTHENTICATE, challenge);
    }
}

fn invalid_dpop_proof_response(description: &str) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_dpop_proof", description)
}

fn invalid_dpop_access_response(error: &str, description: &str) -> HttpResponse {
    let mut response = oauth_error(StatusCode::UNAUTHORIZED, error, description);
    let challenge = format!("DPoP error=\"{error}\", algs=\"EdDSA ES256 RS256\"");
    if let Ok(value) = actix_web::http::header::HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(actix_web::http::header::WWW_AUTHENTICATE, value);
    }
    response
}

fn dpop_nonce_response(protected_resource: bool, nonce: &str) -> HttpResponse {
    let mut response = if protected_resource {
        invalid_dpop_access_response(
            "use_dpop_nonce",
            "the server requires a nonce in the DPoP proof",
        )
    } else {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "use_dpop_nonce",
            "the authorization server requires a nonce in the DPoP proof",
        )
    };
    if let Ok(value) = actix_web::http::header::HeaderValue::from_str(nonce) {
        response.headers_mut().insert(
            actix_web::http::header::HeaderName::from_static("dpop-nonce"),
            value,
        );
    }
    response
}

fn consent_scopes(scopes: &[String], messages: &crate::configuration::UiMessages) -> Vec<String> {
    scopes
        .iter()
        .map(|scope| match scope.as_str() {
            "openid" => messages.scope_openid.clone(),
            "profile" => messages.scope_profile.clone(),
            "email" => messages.scope_email.clone(),
            "offline_access" => messages.scope_offline_access.clone(),
            scope => format!("{} {scope}", messages.scope_custom_prefix),
        })
        .collect()
}

fn consent_authorization_details(
    snapshot: &crate::configuration::Snapshot,
    details: &Value,
) -> Vec<ConsentAuthorizationDetail> {
    details
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|detail| {
            let type_id = detail.get("type")?.as_str()?;
            let name = snapshot
                .authorization_detail_type(type_id)
                .map_or(type_id, |definition| definition.name.as_str())
                .to_owned();
            Some(ConsentAuthorizationDetail {
                name,
                payload: serde_json::to_string_pretty(detail).ok()?,
            })
        })
        .collect()
}

fn authorization_consent_required(
    client: &crate::configuration::Client,
    authorization: &AuthorizationRequest,
) -> bool {
    client.consent_required.unwrap_or(true)
        || authorization.has_prompt("consent")
        || authorization.requests_scope("offline_access")
        || authorization.authorization_details.is_some()
}

fn token_authorization_details(
    form: &TokenForm,
    snapshot: &crate::configuration::Snapshot,
    client: &crate::configuration::Client,
) -> Result<Option<Value>, HttpResponse> {
    form.authorization_details
        .as_deref()
        .map(|serialized| {
            validated_authorization_details(Some(serialized), snapshot, client).map_err(|error| {
                oauth_error(StatusCode::BAD_REQUEST, error.code, error.description)
            })
        })
        .transpose()
}

fn authorization_details_currently_allowed(
    snapshot: &crate::configuration::Snapshot,
    client: &crate::configuration::Client,
    details: &Value,
) -> bool {
    if details.as_array().is_some_and(Vec::is_empty) {
        return true;
    }
    serde_json::to_string(details).is_ok_and(|serialized| {
        validated_authorization_details(Some(&serialized), snapshot, client).is_ok()
    })
}

fn insert_authorization_details(response: &mut Value, details: &Value) {
    if !details.as_array().is_some_and(Vec::is_empty)
        && let Some(response) = response.as_object_mut()
    {
        response.insert("authorization_details".to_owned(), details.clone());
    }
}

fn normalized_scopes(scope: &str) -> Vec<String> {
    let mut scopes = Vec::new();
    for value in scope.split_ascii_whitespace() {
        if !scopes.iter().any(|scope| scope == value) {
            scopes.push(value.to_owned());
        }
    }
    scopes
}

fn verify_pkce(challenge: Option<&str>, verifier: Option<&str>) -> bool {
    match (challenge, verifier) {
        (None, None | Some("")) => true,
        (Some(challenge), Some(verifier)) if valid_pkce_verifier(verifier) => {
            let calculated = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            constant_time_eq::constant_time_eq(challenge.as_bytes(), calculated.as_bytes())
        }
        _ => false,
    }
}

fn valid_pkce_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn secure_request(request: &HttpRequest) -> bool {
    secure_request_with_proxy_trust(request, forwarded_headers_trusted())
}

fn secure_request_with_proxy_trust(request: &HttpRequest, trust_proxy_headers: bool) -> bool {
    request.uri().scheme_str() == Some("https")
        || (trust_proxy_headers
            && request
                .headers()
                .get("x-forwarded-proto")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .is_some_and(|scheme| scheme.trim().eq_ignore_ascii_case("https")))
}

fn forwarded_headers_trusted() -> bool {
    std::env::var("TRUST_PROXY_HEADERS")
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        || std::env::var_os("VERCEL").is_some()
}

fn authentication_remote_address(request: &HttpRequest, trust_proxy_headers: bool) -> String {
    if trust_proxy_headers
        && let Some(address) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
    {
        return address.to_string();
    }
    request
        .peer_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn authentication_rate_limit_keys(
    issuer_id: &str,
    remote_address: &str,
    identifier: Option<&str>,
) -> Vec<String> {
    let mut keys = vec![format!("network:{remote_address}")];
    if let Some(identifier) = identifier {
        keys.push(format!(
            "identifier:{issuer_id}:{}",
            identifier.trim().to_lowercase()
        ));
    }
    keys
}

fn authorization_session_cookie_should_clear(
    snapshot: &crate::configuration::Snapshot,
    issuer_id: &str,
    subject: Option<&str>,
    authentication_satisfied: bool,
) -> bool {
    let Some(subject) = subject else {
        return false;
    };
    let Some(user) = snapshot.user(subject) else {
        return true;
    };
    user.supports_issuer(issuer_id) && !authentication_satisfied
}

fn valid_csrf(request: &HttpRequest, submitted: &str) -> bool {
    if !valid_opaque_token(submitted) {
        return false;
    }
    let cookie = if secure_request(request) {
        request.cookie("__Host-robine_csrf")
    } else {
        request.cookie("robine_csrf")
    };
    cookie.is_some_and(|cookie| {
        valid_opaque_token(cookie.value())
            && constant_time_eq::constant_time_eq(cookie.value().as_bytes(), submitted.as_bytes())
    })
}

fn valid_opaque_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_submitted_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES
}

fn valid_submitted_password(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_BCRYPT_PASSWORD_BYTES
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
    let cookie = if secure_request(request) {
        request.cookie("__Host-robine_session")
    } else {
        request.cookie("robine_session")
    };
    cookie.map(|cookie| cookie.value().to_owned())
}

async fn invalid_existing_session(request: &HttpRequest, application: &Application) -> bool {
    existing_session(request, application).await.clear_cookie
}

struct ExistingSession {
    subject: Option<String>,
    session_id: Option<String>,
    authenticated_at: Option<chrono::DateTime<Utc>>,
    mfa_verified: bool,
    clear_cookie: bool,
    unavailable: bool,
}

async fn existing_session(request: &HttpRequest, application: &Application) -> ExistingSession {
    let Some(session) = session_token(request) else {
        return ExistingSession {
            subject: None,
            session_id: None,
            authenticated_at: None,
            mfa_verified: false,
            clear_cookie: false,
            unavailable: false,
        };
    };
    let Some(database) = application.database() else {
        return ExistingSession {
            subject: None,
            session_id: None,
            authenticated_at: None,
            mfa_verified: false,
            clear_cookie: false,
            unavailable: true,
        };
    };
    let idle_timeout = application
        .snapshot()
        .configuration
        .authentication
        .session
        .idle_timeout
        .max(1);
    match database
        .validate_session_details(&session, idle_timeout)
        .await
    {
        Ok(Some(validated)) => ExistingSession {
            subject: Some(validated.subject),
            session_id: Some(validated.session_id),
            authenticated_at: Some(validated.authenticated_at),
            mfa_verified: validated.mfa_verified,
            clear_cookie: false,
            unavailable: false,
        },
        Ok(None) => ExistingSession {
            subject: None,
            session_id: None,
            authenticated_at: None,
            mfa_verified: false,
            clear_cookie: true,
            unavailable: false,
        },
        Err(error) => {
            tracing::error!(
                event = "session_validation",
                outcome = "failed",
                %error,
                "failed to validate existing browser session"
            );
            ExistingSession {
                subject: None,
                session_id: None,
                authenticated_at: None,
                mfa_verified: false,
                clear_cookie: false,
                unavailable: true,
            }
        }
    }
}

fn add_session_cookie(
    response: &mut HttpResponse,
    request: &HttpRequest,
    token: &str,
    session_id: &str,
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
    add_op_browser_state_cookie(response, request, session_id, lifetime_seconds);
}

fn add_op_browser_state_cookie(
    response: &mut HttpResponse,
    request: &HttpRequest,
    session_id: &str,
    lifetime_seconds: i64,
) {
    let secure = secure_request(request);
    let name = if secure {
        "__Host-robine_opbs"
    } else {
        "robine_opbs"
    };
    let cookie = Cookie::build(name, op_browser_state(session_id))
        .path("/")
        .http_only(false)
        .secure(secure)
        .same_site(if secure {
            SameSite::None
        } else {
            SameSite::Lax
        })
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

    let opbs_name = if secure {
        "__Host-robine_opbs"
    } else {
        "robine_opbs"
    };
    let mut opbs = Cookie::build(opbs_name, "")
        .path("/")
        .http_only(false)
        .secure(secure)
        .same_site(if secure {
            SameSite::None
        } else {
            SameSite::Lax
        })
        .finish();
    opbs.make_removal();
    let _ = response.add_cookie(&opbs);
}

fn redirect_with_state(uri: &str, state: Option<&str>) -> Option<String> {
    let mut redirect = url::Url::parse(uri).ok()?;
    if let Some(state) = state {
        redirect.query_pairs_mut().append_pair("state", state);
    }
    Some(redirect.to_string())
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    json_response(
        status,
        json!({"error": error, "error_description": description}),
    )
}

fn no_store_json_response(status: StatusCode, body: serde_json::Value) -> HttpResponse {
    json_response(status, body)
}

fn no_store_token_introspection_jwt_response(body: String) -> HttpResponse {
    let mut response = HttpResponse::Ok()
        .content_type("application/token-introspection+jwt")
        .body(body);
    prevent_caching(&mut response);
    response
}

fn prevent_caching(response: &mut HttpResponse) {
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        actix_web::http::header::PRAGMA,
        actix_web::http::header::HeaderValue::from_static("no-cache"),
    );
}

fn no_store_empty_response(status: StatusCode) -> HttpResponse {
    let mut response = HttpResponse::build(status).finish();
    prevent_caching(&mut response);
    response
}

fn redirect_response(location: impl Into<String>) -> HttpResponse {
    HttpResponse::Found()
        .insert_header((actix_web::http::header::LOCATION, location.into()))
        .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
        .insert_header((actix_web::http::header::PRAGMA, "no-cache"))
        .finish()
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("operating system randomness is unavailable");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn op_browser_state(session_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!("robine-id op browser state {session_id}").as_bytes(),
    ))
}

fn calculate_session_state(
    client_id: &str,
    origin: &str,
    browser_state: &str,
    salt: &str,
) -> String {
    let input = format!("{client_id} {origin} {browser_state} {salt}");
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes())),
        salt
    )
}

fn new_session_state(client_id: &str, redirect_uri: &str, session_id: &str) -> Option<String> {
    let redirect = url::Url::parse(redirect_uri).ok()?;
    let origin = redirect.origin().ascii_serialization();
    (origin != "null").then(|| {
        let salt = random_token();
        calculate_session_state(client_id, &origin, &op_browser_state(session_id), &salt)
    })
}

fn remaining_session_lifetime(auth_time: Option<i64>, absolute_timeout: i64) -> i64 {
    auth_time
        .map(|auth_time| {
            auth_time
                .saturating_add(absolute_timeout)
                .saturating_sub(Utc::now().timestamp())
        })
        .unwrap_or(absolute_timeout)
        .clamp(1, absolute_timeout.max(1))
}

async fn css(request: HttpRequest) -> impl Responder {
    let portable = APP_CSS
        .split_once("/* This file is for your main application CSS */")
        .map(|(_, css)| css)
        .unwrap_or(APP_CSS);
    cacheable_static_response(
        &request,
        "text/css; charset=utf-8",
        portable.as_bytes(),
        3600,
    )
}

async fn js(request: HttpRequest) -> impl Responder {
    cacheable_static_response(
        &request,
        "text/javascript; charset=utf-8",
        APP_JS.as_bytes(),
        3600,
    )
}

async fn frontchannel_js(request: HttpRequest) -> impl Responder {
    cacheable_static_response(
        &request,
        "text/javascript; charset=utf-8",
        FRONTCHANNEL_JS.as_bytes(),
        3600,
    )
}

async fn check_session_js(request: HttpRequest) -> impl Responder {
    cacheable_static_response(
        &request,
        "text/javascript; charset=utf-8",
        CHECK_SESSION_JS.as_bytes(),
        3600,
    )
}

async fn brand_mark(request: HttpRequest) -> impl Responder {
    cacheable_static_response(&request, "image/png", BRAND_MARK, 86_400)
}

async fn brand_mark_dark(request: HttpRequest) -> impl Responder {
    cacheable_static_response(&request, "image/png", BRAND_MARK_DARK, 86_400)
}

async fn legacy_logo(request: HttpRequest) -> impl Responder {
    cacheable_static_response(&request, "image/svg+xml", LEGACY_LOGO, 86_400)
}

async fn favicon(request: HttpRequest) -> impl Responder {
    cacheable_static_response(&request, "image/png", FAVICON, 86_400)
}

async fn robots(request: HttpRequest) -> impl Responder {
    cacheable_static_response(&request, "text/plain; charset=utf-8", ROBOTS_TXT, 3600)
}

async fn not_found() -> impl Responder {
    json_response(StatusCode::NOT_FOUND, json!({"error": "not_found"}))
}

fn method_not_allowed(allow: &'static str) -> HttpResponse {
    let mut response = json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        json!({"error": "method_not_allowed"}),
    );
    response.headers_mut().insert(
        actix_web::http::header::ALLOW,
        actix_web::http::header::HeaderValue::from_static(allow),
    );
    response
}

async fn post_method_not_allowed() -> HttpResponse {
    method_not_allowed("POST")
}

async fn get_post_method_not_allowed() -> HttpResponse {
    method_not_allowed("GET, POST")
}

async fn post_options_method_not_allowed() -> HttpResponse {
    method_not_allowed("POST, OPTIONS")
}

async fn get_post_options_method_not_allowed() -> HttpResponse {
    method_not_allowed("GET, POST, OPTIONS")
}

fn protocol_error(
    branding: &crate::configuration::Branding,
    message: &str,
    request_id: &str,
) -> HttpResponse {
    let messages = branding.messages(None);
    html_response(
        StatusCode::BAD_REQUEST,
        ProtocolErrorTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            message,
            request_id,
            messages: &messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
        }
        .render(),
    )
}

fn html_response(status: StatusCode, body: askama::Result<String>) -> HttpResponse {
    match body {
        Ok(body) => HttpResponse::build(status)
            .content_type("text/html; charset=utf-8")
            .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
            .insert_header((actix_web::http::header::PRAGMA, "no-cache"))
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
    let mut response = HttpResponse::build(status).json(body);
    prevent_caching(&mut response);
    response
}

fn cacheable_static_response(
    request: &HttpRequest,
    content_type: &'static str,
    body: &'static [u8],
    max_age: u32,
) -> HttpResponse {
    let etag = format!("W/\"{}\"", hex::encode(Sha256::digest(body)));
    let mut response = if request_etag_matches(request, &etag) {
        HttpResponse::NotModified().finish()
    } else if request.method() == actix_web::http::Method::HEAD {
        HttpResponse::Ok()
            .content_type(content_type)
            .insert_header((actix_web::http::header::CONTENT_LENGTH, body.len()))
            .finish()
    } else {
        HttpResponse::Ok().content_type(content_type).body(body)
    };
    if let Ok(cache_control) = actix_web::http::header::HeaderValue::from_str(&format!(
        "public, max-age={max_age}, stale-while-revalidate=60"
    )) {
        response
            .headers_mut()
            .insert(actix_web::http::header::CACHE_CONTROL, cache_control);
    }
    if let Ok(etag) = actix_web::http::header::HeaderValue::from_str(&etag) {
        response
            .headers_mut()
            .insert(actix_web::http::header::ETAG, etag);
    }
    response
}

fn cacheable_json_response(request: &HttpRequest, body: serde_json::Value) -> HttpResponse {
    let body = body.to_string();
    let etag = format!("W/\"{}\"", hex::encode(Sha256::digest(body.as_bytes())));
    let mut response = if request_etag_matches(request, &etag) {
        HttpResponse::NotModified().finish()
    } else if request.method() == actix_web::http::Method::HEAD {
        HttpResponse::Ok()
            .content_type("application/json")
            .insert_header((actix_web::http::header::CONTENT_LENGTH, body.len()))
            .finish()
    } else {
        HttpResponse::Ok()
            .content_type("application/json")
            .body(body)
    };
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static(
            "public, max-age=300, s-maxage=300, stale-while-revalidate=60",
        ),
    );
    if let Ok(etag) = actix_web::http::header::HeaderValue::from_str(&etag) {
        response
            .headers_mut()
            .insert(actix_web::http::header::ETAG, etag);
    }
    response.headers_mut().insert(
        actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        actix_web::http::header::HeaderValue::from_static("*"),
    );
    response.headers_mut().insert(
        actix_web::http::header::HeaderName::from_static("cross-origin-resource-policy"),
        actix_web::http::header::HeaderValue::from_static("cross-origin"),
    );
    response
}

fn request_etag_matches(request: &HttpRequest, etag: &str) -> bool {
    let expected = etag.strip_prefix("W/").unwrap_or(etag);
    for value in request
        .headers()
        .get_all(actix_web::http::header::IF_NONE_MATCH)
    {
        let Ok(value) = value.to_str() else {
            continue;
        };
        if value.split(',').any(|candidate| {
            let candidate = candidate.trim();
            candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == expected
        }) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{Branding, Issuer, RootConfiguration, Snapshot};
    use actix_web::{App, test};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("captured log lock")
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::writer::MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogWriter(self.0.clone())
        }
    }

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("captured log lock").clone())
                .expect("captured logs are UTF-8")
        }
    }

    fn assert_not_cacheable<B>(response: &actix_web::dev::ServiceResponse<B>) {
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::PRAGMA)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
    }

    fn application() -> Application {
        Application::without_database(Snapshot {
            configuration: RootConfiguration {
                schema_version: 1,
                pairwise_subject_salt_reference: None,
                issuers: vec![Issuer {
                    enabled: true,
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
                authorization_detail_types: vec![],
                authentication: Default::default(),
                reconciliation: Default::default(),
                storage: None,
                telemetry: Default::default(),
            },
            revision: "abc123".to_owned(),
        })
    }

    #[actix_web::test]
    async fn dpop_acceptance_audit_omits_proof_identifiers() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(logs.clone())
            .finish();
        let proof = tokens::VerifiedDpopProof {
            jkt: "secret-proof-thumbprint".to_owned(),
            jti: "secret-proof-identifier".to_owned(),
            nonce: Some("secret-proof-nonce".to_owned()),
        };

        tracing::subscriber::with_default(subscriber, || {
            audit_userinfo_dpop_proof_accepted(&proof);
        });

        let logs = logs.text();
        assert!(logs.contains("dpop_proof"));
        assert!(logs.contains("accepted"));
        assert!(logs.contains("userinfo"));
        assert!(!logs.contains(&proof.jkt));
        assert!(!logs.contains(&proof.jti));
        assert!(!logs.contains(proof.nonce.as_deref().expect("proof nonce")));
    }

    #[actix_web::test]
    async fn token_audit_events_distinguish_rfc8693_from_issuance() {
        for grant in [
            TokenGrant::AuthorizationCode,
            TokenGrant::RefreshToken,
            TokenGrant::ClientCredentials,
            TokenGrant::DeviceCode,
            TokenGrant::Unsupported,
        ] {
            assert_eq!(token_audit_event(grant), "token_issuance");
        }
        assert_eq!(
            token_audit_event(TokenGrant::TokenExchange),
            "token_exchange"
        );
    }

    #[actix_web::test]
    async fn normalizes_only_unambiguous_device_user_codes() {
        assert_eq!(
            normalize_device_user_code("bcdf-ghjk"),
            Some(("BCDFGHJK".to_owned(), "BCDF-GHJK".to_owned()))
        );
        assert_eq!(
            normalize_device_user_code(" BCDF GHJK "),
            Some(("BCDFGHJK".to_owned(), "BCDF-GHJK".to_owned()))
        );
        assert_eq!(normalize_device_user_code("BCDI-GHJK"), None);
        assert_eq!(normalize_device_user_code("BCDF-GHJKX"), None);
        assert_eq!(normalize_device_user_code("BCDF"), None);
    }

    #[actix_web::test]
    async fn canonicalizes_only_trusted_forwarded_authentication_addresses() {
        let trusted = test::TestRequest::default()
            .peer_addr("10.0.0.8:1234".parse().unwrap())
            .insert_header(("x-forwarded-for", "2001:0db8:0:0::1, 10.0.0.7"))
            .to_http_request();
        assert_eq!(authentication_remote_address(&trusted, true), "2001:db8::1");
        assert_eq!(authentication_remote_address(&trusted, false), "10.0.0.8");

        let malformed = test::TestRequest::default()
            .peer_addr("10.0.0.9:1234".parse().unwrap())
            .insert_header(("x-forwarded-for", "attacker-controlled-bucket"))
            .to_http_request();
        assert_eq!(authentication_remote_address(&malformed, true), "10.0.0.9");
    }

    #[actix_web::test]
    async fn rate_limit_keys_protect_network_and_normalized_identifier_independently() {
        assert_eq!(
            authentication_rate_limit_keys("default", "192.0.2.10", Some(" Admin@Example.COM ")),
            vec![
                "network:192.0.2.10".to_owned(),
                "identifier:default:admin@example.com".to_owned(),
            ]
        );
        assert_eq!(
            authentication_rate_limit_keys("default", "192.0.2.10", None),
            vec!["network:192.0.2.10".to_owned()]
        );
        assert_ne!(
            authentication_rate_limit_keys("default", "192.0.2.10", Some("admin@example.com"))[1],
            authentication_rate_limit_keys("other", "192.0.2.10", Some("admin@example.com"))[1]
        );
        assert_eq!(
            authentication_rate_limit_keys("default", "192.0.2.10", None),
            authentication_rate_limit_keys("other", "192.0.2.10", None)
        );
    }

    #[actix_web::test]
    async fn preserves_a_global_session_cookie_on_an_unavailable_tenant() {
        let mut snapshot =
            crate::configuration::Snapshot::load().expect("development configuration should load");
        let subject = snapshot.configuration.users[0].id.clone();
        snapshot.configuration.users[0].issuer_ids = vec!["default".to_owned()];

        assert!(!authorization_session_cookie_should_clear(
            &snapshot,
            "other",
            Some(&subject),
            false,
        ));
        assert!(!authorization_session_cookie_should_clear(
            &snapshot,
            "default",
            Some(&subject),
            true,
        ));
        assert!(authorization_session_cookie_should_clear(
            &snapshot,
            "default",
            Some(&subject),
            false,
        ));
        snapshot.configuration.users[0].enabled = false;
        assert!(authorization_session_cookie_should_clear(
            &snapshot,
            "default",
            Some(&subject),
            false,
        ));
        assert!(!authorization_session_cookie_should_clear(
            &snapshot, "default", None, false,
        ));
    }

    #[actix_web::test]
    async fn serves_oidc_discovery() {
        let application = application();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application.clone()))
                .configure(configure),
        )
        .await;
        let request = test::TestRequest::get()
            .uri("/default/.well-known/openid-configuration")
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
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
        let etag = response
            .headers()
            .get(actix_web::http::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("discovery ETag")
            .to_owned();
        assert!(
            response
                .headers()
                .get(actix_web::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("s-maxage=300"))
        );
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["issuer"], "https://id.example/default");

        let standard_response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/.well-known/openid-configuration/default")
                .to_request(),
        )
        .await;
        assert_eq!(standard_response.status(), StatusCode::OK);
        assert_eq!(
            standard_response
                .headers()
                .get(actix_web::http::header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some(etag.as_str())
        );
        let standard_body: serde_json::Value = test::read_body_json(standard_response).await;
        assert_eq!(standard_body, body);
        assert_eq!(
            body["introspection_endpoint"],
            "https://id.example/default/introspect"
        );
        assert_eq!(
            body["protected_resources"],
            json!(["https://id.example/default/userinfo"])
        );
        assert_eq!(
            body["introspection_signing_alg_values_supported"],
            json!(["RS256"])
        );
        assert_eq!(
            body["revocation_endpoint"],
            "https://id.example/default/revoke"
        );
        assert_eq!(
            body["token_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ])
        );
        assert_eq!(
            body["introspection_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt"
            ])
        );
        assert_eq!(
            body["revocation_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            ])
        );
        assert_eq!(
            body["token_endpoint_auth_signing_alg_values_supported"],
            json!(["EdDSA", "ES256", "HS256", "RS256"])
        );
        assert_eq!(
            body["introspection_endpoint_auth_signing_alg_values_supported"],
            json!(["EdDSA", "ES256", "HS256", "RS256"])
        );
        assert_eq!(
            body["revocation_endpoint_auth_signing_alg_values_supported"],
            json!(["EdDSA", "ES256", "HS256", "RS256"])
        );
        assert_eq!(
            body["response_modes_supported"],
            json!(["query", "form_post", "jwt", "query.jwt", "form_post.jwt"])
        );
        assert_eq!(
            body["authorization_signing_alg_values_supported"],
            json!(["RS256"])
        );
        assert_eq!(
            body["userinfo_signing_alg_values_supported"],
            json!(["RS256"])
        );
        assert_eq!(
            body["dpop_signing_alg_values_supported"],
            json!(["EdDSA", "ES256", "RS256"])
        );
        assert_eq!(
            body["acr_values_supported"],
            json!([crate::tokens::PASSWORD_ACR])
        );
        assert_eq!(body["ui_locales_supported"], json!(["en", "fr"]));
        assert_eq!(body["claims_parameter_supported"], true);
        assert_eq!(body["request_parameter_supported"], true);
        assert_eq!(
            body["request_object_signing_alg_values_supported"],
            json!(["EdDSA", "ES256", "RS256"])
        );
        assert_eq!(body["request_uri_parameter_supported"], true);
        assert_eq!(body["require_pushed_authorization_requests"], false);
        assert_eq!(
            body["pushed_authorization_request_endpoint"],
            "https://id.example/default/par"
        );
        assert_eq!(body["authorization_response_iss_parameter_supported"], true);
        assert_eq!(
            body["check_session_iframe"],
            "https://id.example/default/check-session"
        );

        let strong_etag = etag.strip_prefix("W/").expect("weak discovery ETag");
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/default/.well-known/openid-configuration")
                .insert_header((actix_web::http::header::IF_NONE_MATCH, strong_etag))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some(etag.as_str())
        );

        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::HEAD)
                .uri("/default/.well-known/openid-configuration")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some(etag.as_str())
        );
        assert!(
            response
                .headers()
                .get(actix_web::http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.parse::<usize>().is_ok_and(|length| length > 0))
        );
        assert!(test::read_body(response).await.is_empty());

        let mut changed = application.snapshot().as_ref().clone();
        changed.configuration.issuers[0]
            .scopes
            .push("email".to_owned());
        changed.revision = "changed".to_owned();
        assert_eq!(
            application.activate_snapshot(changed),
            crate::ReconciliationOutcome::Activated
        );
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/default/.well-known/openid-configuration")
                .insert_header((actix_web::http::header::IF_NONE_MATCH, etag.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_ne!(
            response
                .headers()
                .get(actix_web::http::header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some(etag.as_str())
        );

        for uri in [
            "/.well-known/oauth-authorization-server/default",
            "/default/.well-known/oauth-authorization-server",
        ] {
            let response =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                response
                    .headers()
                    .contains_key(actix_web::http::header::ETAG)
            );
            assert!(
                response
                    .headers()
                    .get(actix_web::http::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.contains("s-maxage=300"))
            );
            let oauth_metadata: serde_json::Value = test::read_body_json(response).await;
            assert_eq!(oauth_metadata["issuer"], "https://id.example/default");
            assert_eq!(
                oauth_metadata["authorization_endpoint"],
                "https://id.example/default/authorize"
            );
            assert_eq!(
                oauth_metadata["token_endpoint"],
                "https://id.example/default/token"
            );
            assert_eq!(oauth_metadata["response_types_supported"], json!(["code"]));
            assert_eq!(
                oauth_metadata["code_challenge_methods_supported"],
                json!(["S256"])
            );
            assert_eq!(
                oauth_metadata["authorization_response_iss_parameter_supported"],
                true
            );
        }

        for uri in [
            "/default/.well-known/openid-configuration",
            "/.well-known/openid-configuration/default",
            "/.well-known/oauth-authorization-server/default",
            "/default/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource/default/userinfo",
            "/default/jwks.json",
        ] {
            let response = test::call_service(
                &app,
                test::TestRequest::default()
                    .method(actix_web::http::Method::OPTIONS)
                    .uri(uri)
                    .insert_header(("origin", "https://browser.example"))
                    .insert_header(("access-control-request-method", "GET"))
                    .insert_header(("access-control-request-headers", "If-None-Match"))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT, "{uri}");
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|value| value.to_str().ok()),
                Some("*"),
                "{uri}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_METHODS)
                    .and_then(|value| value.to_str().ok()),
                Some("GET, HEAD, OPTIONS"),
                "{uri}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_HEADERS)
                    .and_then(|value| value.to_str().ok()),
                Some("If-None-Match"),
                "{uri}"
            );
            assert_eq!(
                response
                    .headers()
                    .get("access-control-max-age")
                    .and_then(|value| value.to_str().ok()),
                Some("600"),
                "{uri}"
            );
            assert!(test::read_body(response).await.is_empty(), "{uri}");
        }

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/.well-known/oauth-authorization-server/missing")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "invalid_request");
    }

    #[actix_web::test]
    async fn serves_cacheable_user_info_protected_resource_metadata() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/.well-known/oauth-protected-resource/default/userinfo")
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        assert!(
            response
                .headers()
                .get(actix_web::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("s-maxage=300"))
        );
        let etag = response
            .headers()
            .get(actix_web::http::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("resource metadata ETag")
            .to_owned();
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["resource"], "https://id.example/default/userinfo");
        assert_eq!(
            body["authorization_servers"],
            json!(["https://id.example/default"])
        );
        assert_eq!(body["bearer_methods_supported"], json!(["header"]));
        assert_eq!(
            body["dpop_signing_alg_values_supported"],
            json!(["EdDSA", "ES256", "RS256"])
        );

        let not_modified = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/.well-known/oauth-protected-resource/default/userinfo")
                .insert_header((actix_web::http::header::IF_NONE_MATCH, etag))
                .to_request(),
        )
        .await;
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

        let missing = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/.well-known/oauth-protected-resource/missing/userinfo")
                .to_request(),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn requires_par_globally_or_for_a_selected_client_on_get_and_post() {
        let mut snapshot = application().snapshot().as_ref().clone();
        snapshot
            .configuration
            .clients
            .push(crate::configuration::Client {
                enabled: true,
                issuer_ids: vec![],
                id: "par-required-client".to_owned(),
                name: "PAR required".to_owned(),
                client_type: "public".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier: None,
                redirect_uris: vec!["https://app.example/callback".to_owned()],
                post_logout_redirect_uris: vec![],
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                resources: vec![],
                scopes: vec!["openid".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                pkce_required: None,
                nonce_required: None,
                consent_required: None,
                introspection_allowed: false,
                userinfo_signed_response_alg: None,
                require_pushed_authorization_requests: true,
                require_signed_request_object: false,
                request_object_jwks: None,
                required_acr: None,
                max_authentication_age: None,
                actor_token_exchange_allowed: false,
                authorized_actor_clients: vec![],
                authorization_details_types: vec![],
                authentication_method: None,
                secret_reference: None,
                jwks: None,
                branding: None,
            });
        let application = Application::without_database(snapshot);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application.clone()))
                .configure(configure),
        )
        .await;
        let form = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", "par-required-client"),
            ("redirect_uri", "https://app.example/callback"),
            ("scope", "openid"),
            ("state", "mandatory-par-state"),
            ("nonce", "mandatory-par-nonce"),
            (
                "code_challenge",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("code_challenge_method", "S256"),
        ])
        .expect("authorization form");

        for request in [
            test::TestRequest::get()
                .uri(&format!("/default/authorize?{form}"))
                .to_request(),
            test::TestRequest::post()
                .uri("/default/authorize")
                .insert_header((
                    actix_web::http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                ))
                .set_payload(form.clone())
                .to_request(),
        ] {
            let response = test::call_service(&app, request).await;
            assert_eq!(response.status(), StatusCode::FOUND);
            let location = response
                .headers()
                .get(actix_web::http::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .expect("authorization error redirect");
            assert!(location.contains("error=invalid_request"));
            assert!(location.contains("state=mandatory-par-state"));
        }

        let mut globally_required = application.snapshot().as_ref().clone();
        globally_required.configuration.clients[0].require_pushed_authorization_requests = false;
        globally_required.configuration.issuers[0]
            .token_policy
            .require_pushed_authorization_requests = true;
        globally_required.revision = "globally-required".to_owned();
        assert_eq!(
            application.activate_snapshot(globally_required),
            crate::ReconciliationOutcome::Activated
        );
        let discovery = DiscoveryDocument::build(&application.snapshot(), "default")
            .expect("mandatory PAR discovery");
        assert!(discovery.require_pushed_authorization_requests);
    }

    #[actix_web::test]
    async fn discovers_the_issuer_with_privacy_preserving_webfinger() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;

        for account in ["known", "not-a-configured-user"] {
            let query = serde_urlencoded::to_string([
                ("resource", format!("acct:{account}@id.example")),
                ("rel", OIDC_ISSUER_REL.to_owned()),
            ])
            .expect("WebFinger query");
            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(&format!("/.well-known/webfinger?{query}"))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/jrd+json")
            );
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|value| value.to_str().ok()),
                Some("*")
            );
            let body: Value = test::read_body_json(response).await;
            assert_eq!(body["subject"], format!("acct:{account}@id.example"));
            assert_eq!(body["links"][0]["rel"], OIDC_ISSUER_REL);
            assert_eq!(body["links"][0]["href"], "https://id.example/default");
        }

        let query = serde_urlencoded::to_string([
            ("resource", "https://id.example/default/user"),
            ("rel", "https://example.invalid/unrelated"),
        ])
        .expect("filtered WebFinger query");
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/.well-known/webfinger?{query}"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["links"], json!([]));

        let query = serde_urlencoded::to_string([("resource", "acct:user@other.example")])
            .expect("unknown WebFinger query");
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/.well-known/webfinger?{query}"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn serves_cacheable_cross_origin_webfinger_transport() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let query = serde_urlencoded::to_string([
            ("resource", "acct:browser@id.example"),
            ("rel", OIDC_ISSUER_REL),
        ])
        .expect("WebFinger query");
        let uri = format!("/.well-known/webfinger?{query}");

        let response =
            test::call_service(&app, test::TestRequest::get().uri(&uri).to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/jrd+json")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
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
        let etag = response
            .headers()
            .get(actix_web::http::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("WebFinger ETag")
            .to_owned();
        assert!(etag.starts_with("W/\""));
        let body = test::read_body(response).await;

        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::HEAD)
                .uri(&uri)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some(body.len().to_string().as_str())
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some(etag.as_str())
        );
        assert!(test::read_body(response).await.is_empty());

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&uri)
                .insert_header((
                    actix_web::http::header::IF_NONE_MATCH,
                    etag.strip_prefix("W/").expect("weak WebFinger ETag"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
        assert!(test::read_body(response).await.is_empty());

        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/.well-known/webfinger")
                .insert_header((actix_web::http::header::ORIGIN, "https://browser.example"))
                .insert_header((
                    actix_web::http::header::ACCESS_CONTROL_REQUEST_METHOD,
                    "GET",
                ))
                .insert_header((
                    actix_web::http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "If-None-Match",
                ))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_METHODS)
                .and_then(|value| value.to_str().ok()),
            Some("GET, HEAD, OPTIONS")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_HEADERS)
                .and_then(|value| value.to_str().ok()),
            Some("If-None-Match")
        );
    }

    #[actix_web::test]
    async fn keeps_unready_health_responses_non_sensitive() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/health/ready").to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::PRAGMA)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body, json!({"status": "not_ready"}));

        for (uri, expected_status, expected_length) in [
            ("/health/live", StatusCode::OK, r#"{"status":"live"}"#.len()),
            (
                "/health/ready",
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"status":"not_ready"}"#.len(),
            ),
        ] {
            let response = test::call_service(
                &app,
                test::TestRequest::default()
                    .method(actix_web::http::Method::HEAD)
                    .uri(uri)
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), expected_status, "{uri}");
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("no-store"),
                "{uri}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok()),
                Some(expected_length),
                "{uri}"
            );
            assert!(test::read_body(response).await.is_empty(), "{uri}");
        }
    }

    #[actix_web::test]
    async fn rejects_unknown_discovery_issuers_with_a_standard_error() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        for uri in [
            "/missing/.well-known/openid-configuration",
            "/.well-known/openid-configuration/missing",
        ] {
            let response =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            let body: serde_json::Value = test::read_body_json(response).await;
            assert_eq!(body["error"], "invalid_request");
            assert!(!body.to_string().contains("default"));
        }

        let disabled_application = application();
        let mut disabled_snapshot = disabled_application.snapshot().as_ref().clone();
        disabled_snapshot.configuration.issuers[0].enabled = false;
        disabled_snapshot.revision = "disabled-issuer".to_owned();
        assert_eq!(
            disabled_application.activate_snapshot(disabled_snapshot),
            crate::ReconciliationOutcome::Activated
        );
        let disabled_app = test::init_service(
            App::new()
                .app_data(web::Data::new(disabled_application))
                .configure(configure),
        )
        .await;
        for uri in [
            "/default/.well-known/openid-configuration",
            "/.well-known/openid-configuration/default",
            "/.well-known/oauth-authorization-server/default",
            "/default/jwks.json",
        ] {
            let response = test::call_service(
                &disabled_app,
                test::TestRequest::get().uri(uri).to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
        let webfinger_query =
            serde_urlencoded::to_string([("resource", "https://id.example/default/user")])
                .expect("WebFinger query");
        let response = test::call_service(
            &disabled_app,
            test::TestRequest::get()
                .uri(&format!("/.well-known/webfinger?{webfinger_query}"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = test::call_service(
            &disabled_app,
            test::TestRequest::get().uri("/").to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[actix_web::test]
    async fn renders_the_request_reference_on_local_protocol_errors() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let request = test::TestRequest::get()
            .uri("/default/authorize")
            .insert_header(("x-request-id", "protocol_error.123"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("form_post body");
        let body = String::from_utf8(body.to_vec()).expect("UTF-8 protocol error");
        assert!(body.contains("id=\"protocol-error\""));
        assert!(body.contains("protocol_error.123"));
        assert!(body.contains("Return home"));
    }

    #[actix_web::test]
    async fn serves_the_rust_documentation_page() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let response =
            test::call_service(&app, test::TestRequest::get().uri("/docs").to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::PRAGMA)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        let body = test::read_body(response).await;
        let body = String::from_utf8(body.to_vec()).expect("UTF-8 documentation");
        assert!(body.contains("Authorization Code with PKCE"));
        assert!(body.contains("Rich Authorization"));
        assert!(body.contains("authorization_details"));
        assert!(body.contains("RP-Initiated Logout"));
        assert!(body.contains("/default/.well-known/openid-configuration"));
    }

    #[actix_web::test]
    async fn serves_accessible_duplicate_safe_form_enhancements() {
        let app = test::init_service(App::new().configure(configure)).await;
        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/assets/app.js").to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/javascript; charset=utf-8")
        );
        let javascript = String::from_utf8(test::read_body(response).await.to_vec())
            .expect("JavaScript asset is UTF-8");
        assert!(javascript.contains("document.addEventListener(\"submit\""));
        assert!(javascript.contains("event.preventDefault()"));
        assert!(javascript.contains("aria-busy"));
        assert!(javascript.contains("aria-disabled"));
        assert!(javascript.contains("autoSubmitForm.requestSubmit()"));
        assert!(!javascript.contains(".disabled = true"));

        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/assets/app.css").to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let stylesheet = String::from_utf8(test::read_body(response).await.to_vec())
            .expect("stylesheet asset is UTF-8");
        assert!(stylesheet.contains("form[aria-busy=\"true\"]"));
        assert!(stylesheet.contains("button.is-submitting::after"));
        assert!(stylesheet.contains("@media (prefers-reduced-motion: reduce)"));
    }

    #[actix_web::test]
    async fn serves_the_complete_embedded_asset_set_with_conditional_caching() {
        let app = test::init_service(App::new().configure(configure)).await;
        let mut robots_etag = None;

        for (uri, content_type, body, max_age) in [
            ("/favicon.ico", "image/png", FAVICON, 86_400),
            (
                "/images/brand/robine-mark.png",
                "image/png",
                BRAND_MARK,
                86_400,
            ),
            (
                "/images/brand/robine-mark-dark.png",
                "image/png",
                BRAND_MARK_DARK,
                86_400,
            ),
            ("/images/logo.svg", "image/svg+xml", LEGACY_LOGO, 86_400),
            ("/robots.txt", "text/plain; charset=utf-8", ROBOTS_TXT, 3600),
        ] {
            let response =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some(content_type),
                "{uri}"
            );
            let expected_cache_control =
                format!("public, max-age={max_age}, stale-while-revalidate=60");
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some(expected_cache_control.as_str()),
                "{uri}"
            );
            let etag = response
                .headers()
                .get(actix_web::http::header::ETAG)
                .and_then(|value| value.to_str().ok())
                .expect("embedded asset ETag")
                .to_owned();
            if uri == "/robots.txt" {
                robots_etag = Some(etag);
            }
            assert_eq!(test::read_body(response).await.as_ref(), body, "{uri}");
        }

        assert_eq!(ROBOTS_TXT, b"User-agent: *\nDisallow: /\n");
        let robots_etag = robots_etag.expect("robots ETag");
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/robots.txt")
                .insert_header((actix_web::http::header::IF_NONE_MATCH, robots_etag.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some(robots_etag.as_str())
        );
        assert!(test::read_body(response).await.is_empty());

        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::HEAD)
                .uri("/favicon.ico")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let expected_content_length = FAVICON.len().to_string();
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some(expected_content_length.as_str())
        );
        assert!(
            response
                .headers()
                .contains_key(actix_web::http::header::ETAG)
        );
        assert!(test::read_body(response).await.is_empty());
    }

    #[actix_web::test]
    async fn compresses_only_explicitly_negotiated_public_responses() {
        let app = test::init_service(App::new().configure(configure)).await;
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/assets/app.css")
                .insert_header((actix_web::http::header::ACCEPT_ENCODING, "gzip"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            Some("gzip")
        );
        assert!(
            response
                .headers()
                .get_all(actix_web::http::header::VARY)
                .filter_map(|value| value.to_str().ok())
                .any(|value| value
                    .split(',')
                    .any(|name| name.trim().eq_ignore_ascii_case("accept-encoding")))
        );
        assert!(
            response
                .headers()
                .get(actix_web::http::header::ETAG)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("W/\""))
        );
        let body = test::read_body(response).await;
        assert!(body.starts_with(&[0x1f, 0x8b]));

        let response = test::call_service(
            &app,
            test::TestRequest::get().uri("/assets/app.css").to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !response
                .headers()
                .contains_key(actix_web::http::header::CONTENT_ENCODING)
        );
        let body = test::read_body(response).await;
        assert!(std::str::from_utf8(&body).is_ok_and(|body| body.contains(".auth-shell")));
    }

    #[actix_web::test]
    async fn renders_configured_favicon_and_font_family() {
        let base = application();
        let mut snapshot = (*base.snapshot()).clone();
        snapshot.configuration.branding.favicon = Some("/favicon.svg".to_owned());
        snapshot.configuration.branding.font_family =
            Some("Atkinson Hyperlegible, sans-serif".to_owned());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(Application::without_database(snapshot)))
                .configure(configure),
        )
        .await;
        let response =
            test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
        let body = test::read_body(response).await;
        let body = String::from_utf8(body.to_vec()).expect("UTF-8 home page");
        assert!(body.contains("rel=\"icon\" href=\"/favicon.svg?rev=abc123\""));
        assert!(body.contains("--auth-font: Atkinson Hyperlegible, sans-serif"));
    }

    #[actix_web::test]
    async fn renders_the_complete_requested_locale_on_the_login_page() {
        let snapshot = Snapshot::load().expect("development configuration should load");
        let branding = snapshot.branding(Some("default"), Some("development-client"));
        let messages = branding.messages(Some("fr-FR en"));
        let body = LoginTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id: "default",
            client_name: "Development Client",
            transaction: "opaque-browser-authorization-transaction",
            csrf_token: "csrf",
            identifier: "admin@example.com",
            has_error: false,
            error: None,
            messages: &messages,
            logo: branding.logo.as_deref(),
            favicon: branding.favicon.as_deref(),
            font_family: branding.font_family.as_deref(),
            support_url: branding.support_url.as_deref(),
            privacy_url: branding.privacy_url.as_deref(),
            terms_url: branding.terms_url.as_deref(),
        }
        .render()
        .expect("localized login page");
        assert!(body.contains("<html lang=\"fr\">"));
        assert!(body.contains("Heureux de vous revoir"));
        assert!(body.contains("Connectez-vous pour continuer avec"));
        assert!(body.contains("data-show-label=\"Afficher\""));
        assert!(!body.contains("name=\"login_hint\""));
        assert!(body.contains("name=\"identifier\" type=\"text\" value=\"admin@example.com\""));
        assert!(!body.contains("<nav class=\"legal-links\""));
    }

    #[actix_web::test]
    async fn renders_an_accessible_secret_free_totp_challenge() {
        let branding = Branding::default();
        let messages = branding.messages(None);
        let body = TotpTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            client_name: "Client <unsafe>",
            transaction: "opaque-mfa-transaction",
            form_action: "/default/authorize",
            transaction_field: "mfa_transaction",
            action_value: None,
            csrf_token: "csrf",
            has_error: false,
            error: None,
            messages: &messages,
            logo: None,
            favicon: None,
            font_family: None,
            support_url: None,
            privacy_url: None,
            terms_url: None,
        }
        .render()
        .expect("TOTP template");
        assert!(body.contains("/assets/app.js"));
        assert!(body.contains("autocomplete=\"one-time-code\""));
        assert!(body.contains("inputmode=\"numeric\""));
        assert!(body.contains("pattern=\"[0-9]{6}\""));
        assert!(body.contains("name=\"mfa_transaction\" value=\"opaque-mfa-transaction\""));
        assert!(!body.contains("Client <unsafe>"));
        assert!(body.contains("Client &#60;unsafe&#62;"));
        assert!(!body.to_ascii_lowercase().contains("secret"));
    }

    #[actix_web::test]
    async fn accepts_a_form_serialized_authorization_request() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/default/authorize")
                .set_form([
                    ("response_type", "code"),
                    ("client_id", "development-client"),
                    ("redirect_uri", "http://localhost:4002/callback"),
                    ("scope", "openid profile email"),
                    ("state", "post-state"),
                    ("nonce", "post-nonce"),
                    (
                        "code_challenge",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("code_challenge_method", "S256"),
                    ("acr_values", crate::configuration::MFA_ACR),
                    (
                        "claims",
                        r#"{"id_token":{"acr":{"essential":true,"value":"urn:robine-id:acr:password+totp"}}}"#,
                    ),
                    ("future_extension", "ignored"),
                ])
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "temporarily_unavailable");
    }

    #[actix_web::test]
    async fn applies_optional_nonce_and_request_object_rules_to_authorization_post() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application))
                .configure(configure),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/default/authorize")
                .set_form([
                    ("response_type", "code"),
                    ("client_id", "penpot"),
                    (
                        "redirect_uri",
                        "https://penpot.base59.dev/api/auth/oidc/callback",
                    ),
                    ("scope", "openid profile email"),
                    ("state", "nonce-optional"),
                ])
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "temporarily_unavailable");

        for (parameter, value, expected_error) in [
            (
                "request",
                "header.payload.signature",
                "invalid_request_object",
            ),
            (
                "request_uri",
                "https://client.example/request.jwt",
                "request_uri_not_supported",
            ),
        ] {
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/default/authorize")
                    .set_form(vec![
                        ("response_type", "code"),
                        ("client_id", "development-client"),
                        ("redirect_uri", "http://localhost:4002/callback"),
                        ("scope", "openid profile email"),
                        ("state", "unsupported-request"),
                        ("nonce", "nonce"),
                        (
                            "code_challenge",
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        ),
                        ("code_challenge_method", "S256"),
                        (parameter, value),
                    ])
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FOUND);
            let location = response
                .headers()
                .get(actix_web::http::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .expect("authorization error redirect");
            assert!(location.contains(&format!("error={expected_error}")));
            assert!(location.contains("state=unsupported-request"));
            assert!(location.contains("iss=https%3A%2F%2Fid.base59.dev%2Fdefault"));
        }
    }

    #[actix_web::test]
    async fn rejects_duplicate_defined_oauth_parameters() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/default/token")
                .insert_header((
                    actix_web::http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                ))
                .set_payload("grant_type=authorization_code&grant_type=refresh_token")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "invalid_request");

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/default/authorize?response_type=code&response_type=token&client_id=development-client&redirect_uri=http%3A%2F%2Flocalhost%3A4002%2Fcallback&scope=openid&state=duplicate&nonce=nonce&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256")
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response
                .headers()
                .get(actix_web::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/html"))
        );
    }

    #[actix_web::test]
    async fn exposes_user_info_through_get_and_post() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;

        for request in [
            test::TestRequest::get()
                .uri("/default/userinfo")
                .to_request(),
            test::TestRequest::post()
                .uri("/default/userinfo")
                .to_request(),
        ] {
            let response = test::call_service(&app, request).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::WWW_AUTHENTICATE)
                    .and_then(|value| value.to_str().ok()),
                Some(
                    "Bearer error=\"invalid_token\", resource_metadata=\"https://id.example/.well-known/oauth-protected-resource/default/userinfo\""
                )
            );
        }
    }

    #[actix_web::test]
    async fn allows_user_info_cors_only_for_registered_client_origins() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/default/userinfo")
                .insert_header(("origin", "http://localhost:4002"))
                .insert_header(("access-control-request-method", "GET"))
                .insert_header(("access-control-request-headers", "authorization, dpop"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-headers")
                .and_then(|value| value.to_str().ok()),
            Some("Authorization, Content-Type, DPoP")
        );

        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/default/userinfo")
                .insert_header(("origin", "https://attacker.example"))
                .insert_header(("access-control-request-method", "POST"))
                .insert_header(("access-control-request-headers", "authorization"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_not_cacheable(&response);
    }

    #[actix_web::test]
    async fn allows_token_and_par_cors_only_for_registered_public_client_origins() {
        let application = Application::without_database(
            Snapshot::load().expect("development configuration should load"),
        );
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application))
                .configure(configure),
        )
        .await;

        for endpoint in ["token", "par"] {
            let response = test::call_service(
                &app,
                test::TestRequest::default()
                    .method(actix_web::http::Method::OPTIONS)
                    .uri(&format!("/default/{endpoint}"))
                    .insert_header(("origin", "http://localhost:4002"))
                    .insert_header(("access-control-request-method", "POST"))
                    .insert_header(("access-control-request-headers", "content-type, dpop"))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
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
        }

        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/default/token")
                .insert_header(("origin", "http://localhost:4002"))
                .insert_header((
                    actix_web::http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                ))
                .set_payload(
                    "grant_type=authorization_code&code=missing&client_id=rust-development-client&redirect_uri=http%3A%2F%2Flocalhost%3A4002%2Fcallback&code_verifier=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_EXPOSE_HEADERS)
                .and_then(|value| value.to_str().ok()),
            Some("DPoP-Nonce")
        );

        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/default/par")
                .insert_header(("origin", "http://localhost:4002"))
                .set_form([
                    ("response_type", "code"),
                    ("client_id", "rust-development-client"),
                    ("redirect_uri", "http://localhost:4002/callback"),
                    ("scope", "openid profile email"),
                    ("state", "browser-par"),
                    ("nonce", "browser-par"),
                    (
                        "code_challenge",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ),
                    ("code_challenge_method", "S256"),
                ])
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );

        for endpoint in ["token", "par"] {
            for origin in ["https://penpot.base59.dev", "https://attacker.example"] {
                let response = test::call_service(
                    &app,
                    test::TestRequest::default()
                        .method(actix_web::http::Method::OPTIONS)
                        .uri(&format!("/default/{endpoint}"))
                        .insert_header(("origin", origin))
                        .insert_header(("access-control-request-method", "POST"))
                        .insert_header(("access-control-request-headers", "content-type"))
                        .to_request(),
                )
                .await;
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert_not_cacheable(&response);
            }
        }
    }

    #[actix_web::test]
    async fn allows_revocation_cors_only_for_registered_public_client_origins() {
        let snapshot = Snapshot::load().expect("development configuration should load");
        for endpoint in ["token", "par", "revoke"] {
            assert!(public_client_cors_origin_allowed(
                &snapshot,
                &format!("/default/{endpoint}"),
                "http://localhost:4002"
            ));
        }
        for path in [
            "/default/introspect",
            "/default/revoke/nested",
            "/missing/revoke",
        ] {
            assert!(!public_client_cors_origin_allowed(
                &snapshot,
                path,
                "http://localhost:4002"
            ));
        }
        assert!(!public_client_cors_origin_allowed(
            &snapshot,
            "/default/revoke",
            "https://attacker.example"
        ));
        let application = Application::without_database(snapshot);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application))
                .configure(configure),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::default()
                .method(actix_web::http::Method::OPTIONS)
                .uri("/default/revoke")
                .insert_header(("origin", "http://localhost:4002"))
                .insert_header(("access-control-request-method", "POST"))
                .insert_header(("access-control-request-headers", "content-type"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_METHODS)
                .and_then(|value| value.to_str().ok()),
            Some("POST")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_HEADERS)
                .and_then(|value| value.to_str().ok()),
            Some("Content-Type")
        );

        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/default/revoke")
                .insert_header(("origin", "http://localhost:4002"))
                .set_form([
                    ("token", "opaque-token"),
                    ("client_id", "rust-development-client"),
                ])
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("http://localhost:4002")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::ACCESS_CONTROL_EXPOSE_HEADERS)
                .and_then(|value| value.to_str().ok()),
            Some("WWW-Authenticate")
        );
        assert_not_cacheable(&response);

        for (origin, allowed) in [
            ("http://localhost:4002", true),
            ("https://attacker.example", false),
        ] {
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/default/revoke")
                    .insert_header(("origin", origin))
                    .set_form([("client_id", "rust-development-client")])
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|value| value.to_str().ok()),
                allowed.then_some(origin)
            );
            assert_not_cacheable(&response);
            let body: Value = test::read_body_json(response).await;
            assert_eq!(body["error"], "invalid_request");
        }

        for (origin, requested_headers) in [
            ("https://attacker.example", "content-type"),
            ("https://penpot.base59.dev", "content-type"),
            ("http://localhost:4002", "authorization"),
        ] {
            let response = test::call_service(
                &app,
                test::TestRequest::default()
                    .method(actix_web::http::Method::OPTIONS)
                    .uri("/default/revoke")
                    .insert_header(("origin", origin))
                    .insert_header(("access-control-request-method", "POST"))
                    .insert_header(("access-control-request-headers", requested_headers))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_not_cacheable(&response);
        }
    }

    #[actix_web::test]
    async fn keeps_default_and_unknown_issuer_errors_non_cacheable() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;

        for uri in ["/not-routed", "/missing/jwks.json"] {
            let response =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_not_cacheable(&response);
        }
    }

    #[actix_web::test]
    async fn rejects_unsupported_protocol_methods_with_exact_allow_headers() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;

        for (method, uri, allow) in [
            (
                actix_web::http::Method::PUT,
                "/default/authorize",
                "GET, POST",
            ),
            (
                actix_web::http::Method::GET,
                "/default/authorize/consent",
                "POST",
            ),
            (
                actix_web::http::Method::GET,
                "/default/par",
                "POST, OPTIONS",
            ),
            (
                actix_web::http::Method::GET,
                "/default/device_authorization",
                "POST",
            ),
            (actix_web::http::Method::PUT, "/default/device", "GET, POST"),
            (
                actix_web::http::Method::GET,
                "/default/token",
                "POST, OPTIONS",
            ),
            (actix_web::http::Method::GET, "/default/introspect", "POST"),
            (
                actix_web::http::Method::GET,
                "/default/revoke",
                "POST, OPTIONS",
            ),
            (
                actix_web::http::Method::PUT,
                "/default/userinfo",
                "GET, POST, OPTIONS",
            ),
            (actix_web::http::Method::PUT, "/default/logout", "GET, POST"),
        ] {
            let response = test::call_service(
                &app,
                test::TestRequest::default()
                    .method(method)
                    .uri(uri)
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{uri}");
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::ALLOW)
                    .and_then(|value| value.to_str().ok()),
                Some(allow),
                "{uri}"
            );
            assert_not_cacheable(&response);
            let body: Value = test::read_body_json(response).await;
            assert_eq!(body, json!({"error": "method_not_allowed"}), "{uri}");
        }
    }

    #[actix_web::test]
    async fn disabled_clients_do_not_authorize_browser_origins() {
        let mut snapshot = Snapshot::load().expect("development configuration should load");
        let mut other = snapshot.configuration.issuers[0].clone();
        other.id = "other".to_owned();
        other.url = "http://127.0.0.1:4001/other".to_owned();
        snapshot.configuration.issuers.push(other);
        let client = snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "rust-development-client")
            .expect("public development client");
        client.issuer_ids = vec!["default".to_owned()];

        assert!(registered_redirect_origin_allowed(
            &snapshot,
            "default",
            "http://localhost:4002",
            Some("rust-development-client"),
            true
        ));
        assert!(!registered_redirect_origin_allowed(
            &snapshot,
            "other",
            "http://localhost:4002",
            Some("rust-development-client"),
            true
        ));
        snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "rust-development-client")
            .expect("public development client")
            .enabled = false;

        assert!(!registered_redirect_origin(
            &snapshot,
            "default",
            "rust-development-client",
            "http://localhost:4002"
        ));
        assert!(!registered_redirect_origin_allowed(
            &snapshot,
            "default",
            "http://localhost:4002",
            Some("rust-development-client"),
            true
        ));
    }

    #[actix_web::test]
    async fn exports_bounded_prometheus_metrics() {
        let application = application();
        application.metrics().record_http_response(
            crate::metrics::HttpMethodClass::Get,
            200,
            std::time::Duration::from_millis(10),
        );
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application.clone()))
                .configure(configure),
        )
        .await;
        for grant_type in [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            DEVICE_CODE_GRANT,
            TOKEN_EXCHANGE_GRANT,
            "attacker-controlled-grant",
        ] {
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/default/token")
                    .set_form([("grant_type", grant_type)])
                    .to_request(),
            )
            .await;
            assert!(!response.status().is_success(), "{grant_type}");
        }
        let userinfo_response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/default/userinfo")
                .to_request(),
        )
        .await;
        assert_eq!(userinfo_response.status(), StatusCode::UNAUTHORIZED);
        let response =
            test::call_service(&app, test::TestRequest::get().uri("/metrics").to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::PRAGMA)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
        let body = test::read_body(response).await;
        let body = String::from_utf8(body.to_vec()).expect("UTF-8 metrics");
        assert!(body.contains("robine_id_http_requests_total 1"));
        assert!(body.contains("robine_id_http_method_requests_total{method=\"GET\"} 1"));
        assert!(body.contains("revision=\"abc123\""));
        assert!(body.contains("robine_id_ready 0"));
        for grant_type in [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "device_code",
            "token_exchange",
            "unsupported",
        ] {
            assert!(
                body.contains(&format!(
                    "robine_id_token_issuance_total{{grant_type=\"{grant_type}\",outcome=\"failure\"}} 1"
                )),
                "{grant_type}"
            );
        }
        assert!(body.contains("robine_id_token_exchange_total{outcome=\"failure\"} 1"));
        assert!(!body.contains("attacker-controlled-grant"));
        assert!(body.contains("robine_id_userinfo_total{outcome=\"failure\"} 1"));
    }

    #[actix_web::test]
    async fn preserves_only_safe_bounded_incoming_correlation_ids() {
        let safe = test::TestRequest::get()
            .insert_header(("x-request-id", "request_123.safe"))
            .to_http_request();
        assert_eq!(correlation_id(&safe), "request_123.safe");

        let unsafe_value = test::TestRequest::get()
            .insert_header(("x-request-id", "contains spaces and user data"))
            .to_http_request();
        let generated = correlation_id(&unsafe_value);
        assert_ne!(generated, "contains spaces and user data");
        assert!(!generated.is_empty());
    }

    #[actix_web::test]
    async fn accepts_only_the_cookie_name_for_the_request_security_context() {
        let insecure_csrf = "i".repeat(43);
        let secure_csrf = "s".repeat(43);
        let loopback_csrf = "l".repeat(43);
        let secure_with_fallback = test::TestRequest::get()
            .uri("https://id.example/default/authorize")
            .cookie(Cookie::new("robine_session", "insecure-session"))
            .cookie(Cookie::new("robine_csrf", insecure_csrf.clone()))
            .to_http_request();
        assert_eq!(session_token(&secure_with_fallback), None);
        assert!(!valid_csrf(&secure_with_fallback, &insecure_csrf));

        let secure = test::TestRequest::get()
            .uri("https://id.example/default/authorize")
            .cookie(Cookie::new("__Host-robine_session", "secure-session"))
            .cookie(Cookie::new("__Host-robine_csrf", secure_csrf.clone()))
            .to_http_request();
        assert_eq!(session_token(&secure).as_deref(), Some("secure-session"));
        assert!(valid_csrf(&secure, &secure_csrf));

        let loopback = test::TestRequest::get()
            .uri("/default/authorize")
            .cookie(Cookie::new("robine_session", "loopback-session"))
            .cookie(Cookie::new("robine_csrf", loopback_csrf.clone()))
            .to_http_request();
        assert_eq!(
            session_token(&loopback).as_deref(),
            Some("loopback-session")
        );
        assert!(valid_csrf(&loopback, &loopback_csrf));
        assert!(!valid_csrf(&loopback, ""));
        assert!(!valid_csrf(&loopback, "short"));

        let spoofed_proxy = test::TestRequest::get()
            .uri("/default/authorize")
            .insert_header(("x-forwarded-proto", "https"))
            .to_http_request();
        assert!(!secure_request_with_proxy_trust(&spoofed_proxy, false));
        assert!(secure_request_with_proxy_trust(&spoofed_proxy, true));
    }

    #[actix_web::test]
    async fn accepts_exactly_one_well_formed_access_token_credential() {
        let valid = test::TestRequest::get()
            .insert_header(("authorization", "bearer opaque-token"))
            .to_http_request();
        assert_eq!(bearer_token(&valid), Some("opaque-token"));

        let dpop = test::TestRequest::get()
            .insert_header(("authorization", "DPoP bound-token"))
            .to_http_request();
        assert_eq!(
            access_token_credential(&dpop),
            Some(("DPoP", "bound-token"))
        );
        assert_eq!(bearer_token(&dpop), None);

        let extra_part = test::TestRequest::get()
            .insert_header(("authorization", "Bearer opaque-token unexpected"))
            .to_http_request();
        assert_eq!(bearer_token(&extra_part), None);

        let multiple = test::TestRequest::get()
            .append_header(("authorization", "Bearer first"))
            .append_header(("authorization", "Bearer second"))
            .to_http_request();
        assert_eq!(bearer_token(&multiple), None);
    }

    #[actix_web::test]
    async fn returns_standard_dpop_nonce_challenges() {
        let authorization_server = dpop_nonce_response(false, "fresh-as-nonce");
        assert_eq!(authorization_server.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            authorization_server
                .headers()
                .get("dpop-nonce")
                .and_then(|value| value.to_str().ok()),
            Some("fresh-as-nonce")
        );

        let resource_server = dpop_nonce_response(true, "fresh-resource-nonce");
        assert_eq!(resource_server.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resource_server
                .headers()
                .get(actix_web::http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("DPoP error=\"use_dpop_nonce\", algs=\"EdDSA ES256 RS256\"")
        );
        assert_eq!(
            resource_server
                .headers()
                .get("dpop-nonce")
                .and_then(|value| value.to_str().ok()),
            Some("fresh-resource-nonce")
        );
    }

    #[actix_web::test]
    async fn negotiates_only_an_enabled_token_introspection_jwt_media_range() {
        for accept in [
            "application/token-introspection+jwt",
            "application/json, application/token-introspection+jwt; q=0.8",
            "APPLICATION/TOKEN-INTROSPECTION+JWT",
        ] {
            let request = test::TestRequest::default()
                .insert_header((actix_web::http::header::ACCEPT, accept))
                .to_http_request();
            assert!(accepts_token_introspection_jwt(&request));
        }
        for accept in [
            "application/json",
            "*/*",
            "application/token-introspection+jwt; q=0",
        ] {
            let request = test::TestRequest::default()
                .insert_header((actix_web::http::header::ACCEPT, accept))
                .to_http_request();
            assert!(!accepts_token_introspection_jwt(&request));
        }
    }

    #[actix_web::test]
    async fn accepts_one_case_insensitive_form_encoded_basic_credential() {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode("client%3Aid:secret%3Awith%2Bcharacters");
        let valid = test::TestRequest::post()
            .insert_header(("authorization", format!("bAsIc {encoded}")))
            .to_http_request();
        assert_eq!(
            basic_credentials(&valid),
            Ok(Some((
                "client:id".to_owned(),
                "secret:with+characters".to_owned()
            )))
        );

        let malformed = test::TestRequest::post()
            .insert_header(("authorization", "Digest value"))
            .to_http_request();
        assert_eq!(basic_credentials(&malformed), Err(()));

        let multiple = test::TestRequest::post()
            .append_header(("authorization", "Basic Y2xpZW50OnNlY3JldA=="))
            .append_header(("authorization", "Basic Y2xpZW50OnNlY3JldA=="))
            .to_http_request();
        assert_eq!(basic_credentials(&multiple), Err(()));
    }

    #[actix_web::test]
    async fn rejects_a_malformed_authorization_header_at_the_token_endpoint() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let request = test::TestRequest::post()
            .uri("/default/token")
            .insert_header(("authorization", "Digest untrusted"))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", "untrusted"),
                ("client_id", "development-client"),
                ("redirect_uri", "http://127.0.0.1:4000/callback"),
                (
                    "code_verifier",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
            ])
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Basic realm=\"token\"")
        );
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "invalid_client");
    }

    #[actix_web::test]
    async fn protects_token_status_endpoints_with_client_authentication() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;

        for (path, realm) in [
            ("/default/introspect", "introspection"),
            ("/default/revoke", "revocation"),
        ] {
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri(path)
                    .set_form([("token", "opaque-token"), ("client_id", "unknown")])
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::WWW_AUTHENTICATE)
                    .and_then(|value| value.to_str().ok()),
                Some(format!("Basic realm=\"{realm}\"").as_str())
            );
            assert_eq!(
                response
                    .headers()
                    .get(actix_web::http::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("no-store")
            );
        }
    }

    #[actix_web::test]
    async fn returns_an_oauth_error_for_an_incomplete_token_form() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let request = test::TestRequest::post()
            .uri("/default/token")
            .insert_header((actix_web::http::header::ACCEPT_ENCODING, "gzip"))
            .set_form([("grant_type", "authorization_code")])
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_not_cacheable(&response);
        assert!(
            !response
                .headers()
                .contains_key(actix_web::http::header::CONTENT_ENCODING)
        );
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "invalid_request");
    }

    #[actix_web::test]
    async fn returns_a_correlated_page_for_an_incomplete_browser_form() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let request = test::TestRequest::post()
            .uri("/default/authorize")
            .insert_header(("x-request-id", "malformed_form.123"))
            .set_form([("client_id", "development-client")])
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = test::read_body(response).await;
        let body = String::from_utf8(body.to_vec()).expect("UTF-8 protocol error");
        assert!(body.contains("The submitted form is incomplete or malformed"));
        assert!(body.contains("malformed_form.123"));
    }

    #[actix_web::test]
    async fn rejects_pkce_verifiers_outside_the_rfc7636_shape() {
        let short = "short";
        let short_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(short.as_bytes()));
        assert!(!verify_pkce(Some(&short_challenge), Some(short)));

        let valid = "a".repeat(43);
        let valid_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(valid.as_bytes()));
        assert!(verify_pkce(Some(&valid_challenge), Some(&valid)));
    }

    #[actix_web::test]
    async fn normalizes_repeated_requested_scopes_as_a_set() {
        assert_eq!(
            normalized_scopes("openid profile openid email profile"),
            vec!["openid", "profile", "email"]
        );
    }

    #[actix_web::test]
    async fn serves_an_origin_bound_embeddable_session_management_iframe() {
        let base = application();
        let mut snapshot = base.snapshot().as_ref().clone();
        snapshot.configuration.clients.push(
            serde_json::from_value(json!({
                "id": "session-client",
                "name": "Session client",
                "type": "public",
                "redirect_uris": ["https://app.example/callback"],
                "scopes": ["openid"],
                "grant_types": ["authorization_code"],
                "authentication_method": "none",
                "pkce_required": true,
                "nonce_required": true
            }))
            .expect("session management client"),
        );
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(Application::without_database(snapshot)))
                .configure(configure),
        )
        .await;

        let mut response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/default/check-session")
                .to_request(),
        )
        .await;
        secure(response.response_mut());
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("x-frame-options"));
        assert_eq!(
            response
                .headers()
                .get("cross-origin-resource-policy")
                .and_then(|value| value.to_str().ok()),
            Some("cross-origin")
        );
        let csp = response
            .headers()
            .get(actix_web::http::header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .expect("iframe CSP");
        assert!(csp.contains("connect-src 'self'"));
        assert!(csp.contains("frame-ancestors *"));
        let body = test::read_body(response).await;
        let body = String::from_utf8(body.to_vec()).expect("UTF-8 iframe");
        assert!(body.contains("data-origin-validation-endpoint="));
        assert!(body.contains("src=\"/assets/check-session.js\""));
        assert!(!body.contains("<script>"));

        let allowed = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/default/check-session/origin?client_id=session-client&origin=https%3A%2F%2Fapp.example")
                .to_request(),
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
        assert_not_cacheable(&allowed);
        let rejected = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/default/check-session/origin?client_id=session-client&origin=https%3A%2F%2Fevil.example")
                .to_request(),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_not_cacheable(&rejected);

        let script = test::call_and_read_body(
            &app,
            test::TestRequest::get()
                .uri("/assets/check-session.js")
                .to_request(),
        )
        .await;
        let script = String::from_utf8(script.to_vec()).expect("UTF-8 script");
        assert!(script.contains("postMessage(status, event.origin)"));
        assert!(script.contains("crypto.subtle.digest"));
        assert!(script.contains("originAllowed(clientId, event.origin)"));
    }

    #[actix_web::test]
    async fn session_state_is_salted_origin_bound_and_uses_a_non_authenticating_cookie() {
        let salt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let browser_state = op_browser_state("public-session-id");
        let state = calculate_session_state(
            "session-client",
            "https://app.example",
            &browser_state,
            salt,
        );
        assert_eq!(state.len(), 87);
        assert!(!state.contains(' '));
        assert_eq!(state.rsplit_once('.').map(|(_, salt)| salt), Some(salt));
        assert_ne!(
            state,
            calculate_session_state(
                "session-client",
                "https://other.example",
                &browser_state,
                salt,
            )
        );

        let request = test::TestRequest::default()
            .uri("https://id.example/default/authorize")
            .to_http_request();
        let mut response = HttpResponse::Ok().finish();
        add_op_browser_state_cookie(&mut response, &request, "public-session-id", 3_600);
        let cookie = response
            .headers()
            .get_all(actix_web::http::header::SET_COOKIE)
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("__Host-robine_opbs="))
            .expect("OP browser state cookie");
        assert!(cookie.contains("SameSite=None"));
        assert!(cookie.contains("Secure"));
        assert!(!cookie.contains("HttpOnly"));
        assert!(!cookie.contains("public-session-id"));
    }

    #[actix_web::test]
    async fn renders_a_cache_disabled_form_post_response_with_a_narrow_csp() {
        let branding = Branding::default();
        let mut response = authorization_client_response(
            "https://app.example/callback?existing=1",
            Some("form_post"),
            &[
                ("code", "code<&>"),
                ("state", "state-value"),
                ("iss", "https://id.example/default"),
            ],
            &branding,
            None,
        )
        .await
        .expect("form_post response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let dynamic_csp = response
            .headers()
            .get(actix_web::http::header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .expect("dynamic form-action CSP")
            .to_owned();
        assert!(dynamic_csp.contains("form-action https://app.example;"));
        assert!(!dynamic_csp.contains("code<&>"));
        secure(&mut response);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CONTENT_SECURITY_POLICY)
                .and_then(|value| value.to_str().ok()),
            Some(dynamic_csp.as_str())
        );
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("form_post body");
        let body = String::from_utf8(body.to_vec()).expect("UTF-8 form_post page");
        assert!(body.contains("action=\"https://app.example/callback?existing=1\""));
        assert!(body.contains("name=\"code\""));
        assert!(!body.contains("value=\"code<&>\""));
        assert!(body.contains("name=\"state\" value=\"state-value\""));
        assert!(body.contains("data-auto-submit"));
    }

    #[actix_web::test]
    async fn keeps_query_as_the_default_authorization_response_mode() {
        let response = authorization_client_response(
            "https://app.example/callback?existing=1",
            None,
            &[("code", "code-value"), ("state", "state-value")],
            &Branding::default(),
            None,
        )
        .await
        .expect("query response");
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("redirect location");
        assert!(location.contains("existing=1"));
        assert!(location.contains("code=code-value"));
        assert!(location.contains("state=state-value"));
    }

    #[actix_web::test]
    async fn offline_access_always_requires_explicit_consent() {
        let client = crate::configuration::Client {
            enabled: true,
            issuer_ids: vec![],
            id: "offline-client".to_owned(),
            name: "Offline client".to_owned(),
            client_type: "public".to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier: None,
            redirect_uris: vec!["https://app.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            resources: vec![],
            scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
            grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
            pkce_required: Some(true),
            nonce_required: Some(true),
            consent_required: Some(false),
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
            authentication_method: Some("none".to_owned()),
            secret_reference: None,
            jwks: None,
            branding: None,
        };
        let mut request = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: client.id.clone(),
            redirect_uri: client.redirect_uris[0].clone(),
            scope: "openid offline_access".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };

        assert!(authorization_consent_required(&client, &request));
        request.scope = "openid".to_owned();
        assert!(!authorization_consent_required(&client, &request));
        request.prompt = Some("consent".to_owned());
        assert!(authorization_consent_required(&client, &request));
        request.prompt = None;
        request.authorization_details = Some(
            json!([{"type": "account_information", "actions": ["read_balances"]}]).to_string(),
        );
        assert!(authorization_consent_required(&client, &request));

        assert!(authentication_context_satisfies(&client, false));
        assert!(authorization_authentication_context_satisfies(
            &client, &request, false
        ));
        let mut mfa_client = client.clone();
        mfa_client.required_acr = Some(crate::configuration::MFA_ACR.to_owned());
        mfa_client.max_authentication_age = Some(300);
        assert!(!authentication_context_satisfies(&mfa_client, false));
        assert!(authentication_context_satisfies(&mfa_client, true));
        request.max_age = Some("600".to_owned());
        assert_eq!(authentication_max_age(&mfa_client, &request), Some(300));
        request.max_age = Some("60".to_owned());
        assert_eq!(authentication_max_age(&mfa_client, &request), Some(60));
        request.max_age = None;
        assert_eq!(authentication_max_age(&mfa_client, &request), Some(300));
        request.claims = Some(
            json!({"id_token": {"acr": {"essential": true, "value": crate::configuration::MFA_ACR}}})
                .to_string(),
        );
        assert!(authorization_requires_mfa(&client, &request));
        assert!(!authorization_authentication_context_satisfies(
            &client, &request, false
        ));
        assert!(authorization_authentication_context_satisfies(
            &client, &request, true
        ));
    }

    #[actix_web::test]
    async fn enforces_essential_id_token_and_userinfo_claim_values() {
        let mut snapshot = application().snapshot().as_ref().clone();
        snapshot.configuration.issuers[0]
            .scopes
            .push("profile".to_owned());
        snapshot.configuration.claims.insert(
            "department".to_owned(),
            crate::configuration::ClaimMapping {
                source: "department".to_owned(),
                scope: "profile".to_owned(),
            },
        );
        let user = crate::configuration::User {
            id: "user-1".to_owned(),
            identifier: "user@example.com".to_owned(),
            password_hash: "unused".to_owned(),
            enabled: true,
            issuer_ids: vec![],
            totp_secret_reference: None,
            name: None,
            email: None,
            claims: serde_json::Map::from_iter([("department".to_owned(), json!("engineering"))]),
        };
        let mut authorization = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "web".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid profile".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: Some(
                json!({
                    "id_token": {"auth_time": {"essential": true}},
                    "userinfo": {"department": {"essential": true, "value": "engineering"}}
                })
                .to_string(),
            ),
            authorization_details: None,
            dpop_jkt: None,
        };
        assert!(essential_claims_satisfied(
            &snapshot,
            "default",
            &authorization,
            &user,
            1_700_000_000,
            false,
        ));

        authorization.claims = Some(
            json!({"userinfo": {"department": {"essential": true, "value": "finance"}}})
                .to_string(),
        );
        assert!(!essential_claims_satisfied(
            &snapshot,
            "default",
            &authorization,
            &user,
            1_700_000_000,
            false,
        ));
    }

    #[actix_web::test]
    async fn merges_only_identical_outer_request_object_parameters() {
        let signed = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "signed-client".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            scope: "openid profile".to_owned(),
            state: "signed-state".to_owned(),
            nonce: "signed-nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: Some("fr".to_owned()),
            prompt: None,
            max_age: None,
            response_mode: Some("form_post".to_owned()),
            resource: Some("https://api.example/resource".to_owned()),
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: Some("header.payload.signature".to_owned()),
            acr_values: Some(crate::configuration::MFA_ACR.to_owned()),
            claims: Some(json!({"id_token": {"acr": {"essential": true}}}).to_string()),
            authorization_details: None,
            dpop_jkt: Some("A".repeat(43)),
        };
        let mut outer = AuthorizationRequest {
            response_type: String::new(),
            client_id: "signed-client".to_owned(),
            redirect_uri: String::new(),
            scope: String::new(),
            state: String::new(),
            nonce: String::new(),
            code_challenge: None,
            code_challenge_method: None,
            ui_locales: None,
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: Some("signed.jwt".to_owned()),
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };
        let merged = merge_signed_authorization_request(&outer, signed.clone())
            .expect("request-object-only outer parameters");
        assert_eq!(merged.state, "signed-state");
        assert!(merged.request_object.is_none());
        assert_eq!(
            merged.dpop_jkt.as_deref(),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
        assert_eq!(
            merged.acr_values.as_deref(),
            Some(crate::configuration::MFA_ACR)
        );
        assert_eq!(merged.claims, signed.claims);
        assert_eq!(merged.id_token_hint, signed.id_token_hint);

        outer.scope = signed.scope.clone();
        assert!(merge_signed_authorization_request(&outer, signed.clone()).is_some());
        outer.id_token_hint = Some("different.header.payload".to_owned());
        assert!(merge_signed_authorization_request(&outer, signed.clone()).is_none());
        outer.id_token_hint = None;
        outer.dpop_jkt = Some("B".repeat(43));
        assert!(merge_signed_authorization_request(&outer, signed.clone()).is_none());
        outer.dpop_jkt = None;
        outer.acr_values = Some(crate::configuration::PASSWORD_ACR.to_owned());
        assert!(merge_signed_authorization_request(&outer, signed.clone()).is_none());
        outer.acr_values = None;
        outer.claims = Some("{ \"id_token\": { \"acr\": { \"essential\": true } } }".to_owned());
        assert!(merge_signed_authorization_request(&outer, signed.clone()).is_some());
        outer.claims = Some(json!({"id_token": {"sub": null}}).to_string());
        assert!(merge_signed_authorization_request(&outer, signed.clone()).is_none());
        outer.claims = None;
        outer.scope = "openid email".to_owned();
        assert!(merge_signed_authorization_request(&outer, signed).is_none());
    }

    #[actix_web::test]
    async fn enforces_per_client_signed_request_object_policy_before_browser_state() {
        let mut snapshot = Snapshot::load().expect("development configuration");
        let client = snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "rust-development-client")
            .expect("development client");
        client.require_signed_request_object = true;
        let application = Application::without_database(snapshot);
        let unsigned = AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: "rust-development-client".to_owned(),
            redirect_uri: "http://localhost:4002/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: "nonce".to_owned(),
            code_challenge: Some("a".repeat(43)),
            code_challenge_method: Some("S256".to_owned()),
            ui_locales: None,
            prompt: None,
            max_age: None,
            response_mode: None,
            resource: None,
            request_object: None,
            request_uri: None,
            login_hint: None,
            id_token_hint: None,
            acr_values: None,
            claims: None,
            authorization_details: None,
            dpop_jkt: None,
        };
        assert!(matches!(
            enforce_signed_request_object_policy("default", unsigned.clone(), &application),
            Err(AuthorizationInputError::SignedRequestObjectRequired(_))
        ));
        let mut signed = unsigned;
        signed.request_object = Some("header.payload.signature".to_owned());
        assert!(enforce_signed_request_object_policy("default", signed, &application).is_ok());
    }

    #[actix_web::test]
    async fn id_token_hint_never_authorizes_a_different_subject() {
        assert!(id_token_hint_matches_subject(None, "user-1"));
        assert!(id_token_hint_matches_subject(Some("user-1"), "user-1"));
        assert!(!id_token_hint_matches_subject(Some("user-2"), "user-1"));
    }

    #[actix_web::test]
    async fn resolves_logout_client_and_hint_audience_consistently() {
        let mut snapshot = (*application().snapshot()).clone();
        snapshot
            .configuration
            .clients
            .push(crate::configuration::Client {
                enabled: true,
                issuer_ids: vec![],
                id: "client-1".to_owned(),
                name: "Client one".to_owned(),
                client_type: "public".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier: None,
                redirect_uris: vec!["https://client.example/callback".to_owned()],
                post_logout_redirect_uris: vec!["https://client.example/signed-out".to_owned()],
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                resources: vec![],
                scopes: vec!["openid".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
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
                authentication_method: None,
                secret_reference: None,
                jwks: None,
                branding: None,
            });

        assert!(
            resolve_logout_client(&snapshot, "default", None, None)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            resolve_logout_client(&snapshot, "default", Some("client-1"), None)
                .unwrap()
                .map(|client| client.id.as_str()),
            Some("client-1")
        );
        assert_eq!(
            resolve_logout_client(&snapshot, "default", None, Some("client-1"))
                .unwrap()
                .map(|client| client.id.as_str()),
            Some("client-1")
        );
        assert_eq!(
            resolve_logout_client(&snapshot, "default", Some("client-1"), Some("client-2"))
                .unwrap_err(),
            LogoutClientError::ClientMismatch
        );
        assert_eq!(
            resolve_logout_client(&snapshot, "default", Some("unknown"), None).unwrap_err(),
            LogoutClientError::UnknownClient
        );
        assert_eq!(
            resolve_logout_client(&snapshot, "default", None, Some("unknown")).unwrap_err(),
            LogoutClientError::UnknownAudience
        );
        snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "client-1")
            .expect("client")
            .issuer_ids = vec!["other".to_owned()];
        assert_eq!(
            resolve_logout_client(&snapshot, "default", Some("client-1"), None).unwrap_err(),
            LogoutClientError::UnknownClient
        );
    }

    #[actix_web::test]
    async fn builds_exact_session_bound_frontchannel_logout_frames_and_csp() {
        let mut snapshot = application().snapshot().as_ref().clone();
        let client: crate::configuration::Client = serde_json::from_value(json!({
            "id": "frontchannel-client",
            "name": "Front-channel client",
            "type": "confidential",
            "redirect_uris": ["https://client.example/callback"],
            "frontchannel_logout_uri": "https://client.example/logout?tenant=one",
            "frontchannel_logout_session_required": true,
            "scopes": ["openid"],
            "grant_types": ["authorization_code"],
            "authentication_method": "client_secret_basic",
            "secret_reference": {"provider": "env", "key": "TEST_FRONTCHANNEL_SECRET"}
        }))
        .expect("front-channel client");
        snapshot.configuration.clients.push(client);
        let targets = vec![crate::database::LogoutTarget {
            subject: "user-1".to_owned(),
            session_id: "session-1".to_owned(),
            issuer: "https://id.example/default".to_owned(),
            client_id: "frontchannel-client".to_owned(),
        }];
        let uris = frontchannel_logout_uris(&snapshot, &targets);
        assert_eq!(uris.len(), 1);
        let uri = url::Url::parse(&uris[0]).expect("front-channel URI");
        assert_eq!(uri.path(), "/logout");
        assert_eq!(
            uri.query_pairs().collect::<Vec<_>>(),
            vec![
                ("tenant".into(), "one".into()),
                ("iss".into(), "https://id.example/default".into()),
                ("sid".into(), "session-1".into())
            ]
        );

        let mut response = HttpResponse::Ok().finish();
        set_frontchannel_content_security_policy(&mut response, &uris);
        let policy = response
            .headers()
            .get(actix_web::http::header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .expect("front-channel CSP");
        assert!(policy.contains("frame-src https://client.example"));
        assert!(!policy.contains("tenant=one"));

        let branding = snapshot.branding(Some("default"), Some("frontchannel-client"));
        let messages = branding.messages(None);
        let rendered = FrontchannelLogoutTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            destination: "https://client.example/signed-out?state=one&next=two",
            logout_uris: &uris,
            messages: &messages,
            logo: None,
            favicon: None,
            font_family: None,
        }
        .render()
        .expect("front-channel template");
        assert!(rendered.contains("data-frontchannel-logout"));
        assert!(rendered.contains("/assets/frontchannel.js"));
        assert!(rendered.contains("sandbox=\"allow-same-origin allow-scripts\""));
        assert!(rendered.contains("state=one&#38;next=two"));

        snapshot.configuration.clients[0].frontchannel_logout_session_required = false;
        let unbound_uris = frontchannel_logout_uris(&snapshot, &targets);
        assert_eq!(unbound_uris, ["https://client.example/logout?tenant=one"]);
    }

    #[actix_web::test]
    async fn accepts_post_serialized_logout_initiation_without_mixing_confirmation_fields() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/default/logout")
                .set_form([("ui_locales", "fr")])
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = test::read_body(response).await;
        assert!(
            body.windows("temporarily_unavailable".len())
                .any(|value| value == b"temporarily_unavailable")
        );

        let mixed = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/default/logout")
                .set_form([
                    ("transaction", "transaction"),
                    ("csrf_token", "csrf"),
                    ("client_id", "client-1"),
                ])
                .to_request(),
        )
        .await;
        assert_eq!(mixed.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn preserves_acr_values_and_claims_in_pushed_authorization_requests() {
        let form = serde_urlencoded::from_str::<PushedAuthorizationForm>(
            "response_type=code&client_id=web&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=state&nonce=nonce&id_token_hint=header.payload.signature&acr_values=urn%3Arobine-id%3Aacr%3Apassword%2Btotp&claims=%7B%22id_token%22%3A%7B%22acr%22%3A%7B%22essential%22%3Atrue%7D%7D%7D&authorization_details=%5B%7B%22type%22%3A%22account_information%22%2C%22actions%22%3A%5B%22read_balances%22%5D%7D%5D",
        )
        .expect("PAR form");
        let (request, _, _, _) = form.into_request();
        assert_eq!(
            request.acr_values.as_deref(),
            Some(crate::configuration::MFA_ACR)
        );
        assert_eq!(
            request.claims.as_deref(),
            Some(r#"{"id_token":{"acr":{"essential":true}}}"#)
        );
        assert_eq!(
            request.id_token_hint.as_deref(),
            Some("header.payload.signature")
        );
        assert_eq!(
            request.authorization_details.as_deref(),
            Some(r#"[{"type":"account_information","actions":["read_balances"]}]"#)
        );
    }

    #[actix_web::test]
    async fn consent_escapes_rich_authorization_details() {
        let branding = Branding::default();
        let messages = branding.messages(None);
        let scopes = vec!["Confirm your identity".to_owned()];
        let details = vec![ConsentAuthorizationDetail {
            name: "Accounts <script>alert(1)</script>".to_owned(),
            payload: "{\"identifier\":\"<img src=x onerror=alert(1)>\"}".to_owned(),
        }];
        let body = ConsentTemplate {
            product_name: "Robine ID",
            primary_color: "#176b70",
            issuer_id: "default",
            client_name: "Dashboard",
            scopes: &scopes,
            authorization_details: &details,
            transaction: "transaction",
            csrf_token: "csrf",
            messages: &messages,
            logo: None,
            favicon: None,
            font_family: None,
            support_url: None,
            privacy_url: None,
            terms_url: None,
        }
        .render()
        .expect("consent template");

        assert!(body.contains("/assets/app.js"));
        assert!(body.contains("Fine-grained access"));
        assert!(body.contains("Accounts &"));
        assert!(body.contains("identifier"));
        assert!(!body.contains("<script>alert(1)</script>"));
        assert!(!body.contains("<img src=x onerror=alert(1)>"));
    }

    #[actix_web::test]
    async fn login_errors_preserve_only_the_non_sensitive_identifier() {
        let branding = Branding::default();
        let messages = branding.messages(None);
        let body = LoginTemplate {
            product_name: &branding.product_name,
            primary_color: &branding.primary_color,
            issuer_id: "default",
            client_name: "Client",
            transaction: "opaque-browser-authorization-transaction",
            csrf_token: "csrf",
            identifier: "admin@example.com",
            has_error: true,
            error: Some("The email or password is incorrect."),
            messages: &messages,
            logo: None,
            favicon: None,
            font_family: None,
            support_url: None,
            privacy_url: None,
            terms_url: None,
        }
        .render()
        .expect("login template");

        assert!(body.contains("value=\"admin@example.com\""));
        assert!(body.contains("name=\"identifier\" type=\"text\""));
        assert!(body.contains("id=\"login-error\""));
        assert!(
            body.contains(
                "name=\"transaction\" value=\"opaque-browser-authorization-transaction\""
            )
        );
        assert!(!body.contains("name=\"client_id\""));
        assert!(!body.contains("name=\"redirect_uri\""));
        assert!(!body.contains("name=\"state\""));
        assert!(!body.contains("name=\"dpop_jkt\""));
        assert!(body.contains("aria-invalid=\"true\""));
        assert!(!body.contains("value=\"change-me\""));
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
        let redirect = redirect_response("https://app.example/callback?code=sensitive");
        assert_eq!(
            redirect
                .headers()
                .get(actix_web::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    #[actix_web::test]
    async fn enforces_the_configured_confidential_client_secret_transport() {
        let expected_secret = std::env::var("PATH").expect("test process PATH");
        let client = crate::configuration::Client {
            enabled: true,
            issuer_ids: vec![],
            id: "confidential".to_owned(),
            name: "Confidential".to_owned(),
            client_type: "confidential".to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier: None,
            redirect_uris: vec!["https://app.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            resources: vec![],
            scopes: vec!["openid".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            pkce_required: Some(false),
            nonce_required: Some(false),
            consent_required: Some(false),
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
            authentication_method: Some("client_secret_post".to_owned()),
            secret_reference: Some(json!({"provider": "env", "key": "PATH"})),
            jwks: None,
            branding: None,
        };

        assert!(authenticate_client(
            &client,
            None,
            None,
            Some("confidential"),
            Some(&expected_secret)
        ));
        assert!(!authenticate_client(
            &client,
            Some("confidential"),
            Some(&expected_secret),
            None,
            None
        ));
    }

    #[actix_web::test]
    async fn rejects_user_info_grants_issued_by_another_issuer() {
        let base = application();
        let mut snapshot = (*base.snapshot()).clone();
        snapshot
            .configuration
            .users
            .push(crate::configuration::User {
                id: "subject".to_owned(),
                identifier: "subject@example.test".to_owned(),
                password_hash: "$2b$12$.JtidA6ZMWny4XaLMozDSOupYHbVNQurj8NkCdM9D3m/g3v3fyXXa"
                    .to_owned(),
                enabled: true,
                issuer_ids: vec![],
                totp_secret_reference: None,
                name: None,
                email: None,
                claims: Default::default(),
            });
        snapshot
            .configuration
            .clients
            .push(crate::configuration::Client {
                enabled: true,
                issuer_ids: vec![],
                id: "client".to_owned(),
                name: "Client".to_owned(),
                client_type: "public".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier: None,
                redirect_uris: vec!["https://app.example/callback".to_owned()],
                post_logout_redirect_uris: vec![],
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                resources: vec![],
                scopes: vec!["openid".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
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
                authentication_method: None,
                secret_reference: None,
                jwks: None,
                branding: None,
            });
        let mut grant = AccessGrant {
            issuer: "https://other.example/default".to_owned(),
            subject: "subject".to_owned(),
            client_id: "client".to_owned(),
            scopes: vec!["openid".to_owned()],
            grant_type: "authorization_code".to_owned(),
            resource: None,
            dpop_jkt: None,
            auth_time: Some(Utc::now().timestamp()),
            mfa_verified: false,
            claims: json!({}),
            authorization_details: Value::Array(vec![]),
            actor: None,
            expires_at: Utc::now() + Duration::minutes(5),
        };

        assert!(!valid_user_info_grant(&snapshot, "default", &grant));
        grant.issuer = "https://id.example/default".to_owned();
        assert!(valid_user_info_grant(&snapshot, "default", &grant));
        snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "client")
            .expect("client")
            .issuer_ids = vec!["other".to_owned()];
        assert!(!valid_user_info_grant(&snapshot, "default", &grant));
        snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "client")
            .expect("client")
            .issuer_ids = vec![];
        assert!(valid_user_info_grant(&snapshot, "default", &grant));
        snapshot
            .configuration
            .users
            .iter_mut()
            .find(|user| user.id == "subject")
            .expect("user")
            .issuer_ids = vec!["other".to_owned()];
        assert!(!valid_user_info_grant(&snapshot, "default", &grant));
        snapshot
            .configuration
            .users
            .iter_mut()
            .find(|user| user.id == "subject")
            .expect("user")
            .issuer_ids = vec![];
        assert!(valid_user_info_grant(&snapshot, "default", &grant));
        grant.authorization_details =
            json!([{"type": "account_information", "actions": ["read_balances"]}]);
        assert!(!valid_user_info_grant(&snapshot, "default", &grant));
        snapshot.configuration.authorization_detail_types.push(
            crate::configuration::AuthorizationDetailType {
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
            .find(|client| client.id == "client")
            .expect("client")
            .authorization_details_types = vec!["account_information".to_owned()];
        assert!(valid_user_info_grant(&snapshot, "default", &grant));

        let now = Utc::now().timestamp();
        {
            let client = snapshot
                .configuration
                .clients
                .iter_mut()
                .find(|client| client.id == "client")
                .expect("client");
            client.required_acr = Some(crate::configuration::MFA_ACR.to_owned());
            client.max_authentication_age = Some(300);
        }
        grant.auth_time = Some(now - 301);
        assert_eq!(
            user_info_step_up_requirement(&snapshot, "default", &grant, now),
            Some(UserInfoStepUpRequirement {
                acr_values: Some(crate::configuration::MFA_ACR.to_owned()),
                max_age: Some(300),
            })
        );
        let response = insufficient_user_authentication_response(
            "Bearer",
            &user_info_step_up_requirement(&snapshot, "default", &grant, now)
                .expect("step-up requirement"),
            Some("https://id.example/.well-known/oauth-protected-resource/default/userinfo"),
        );
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(concat!(
                "Bearer error=\"insufficient_user_authentication\", ",
                "error_description=\"a stronger and more recent authentication is required\", ",
                "acr_values=\"urn:robine-id:acr:password+totp\", max_age=\"300\", ",
                "resource_metadata=\"https://id.example/.well-known/oauth-protected-resource/default/userinfo\""
            ))
        );
        grant.auth_time = Some(now);
        grant.mfa_verified = true;
        assert_eq!(
            user_info_step_up_requirement(&snapshot, "default", &grant, now),
            None
        );

        snapshot
            .configuration
            .users
            .iter_mut()
            .find(|user| user.id == "subject")
            .expect("subject")
            .enabled = false;
        assert!(!valid_user_info_grant(&snapshot, "default", &grant));
        snapshot
            .configuration
            .users
            .iter_mut()
            .find(|user| user.id == "subject")
            .expect("subject")
            .enabled = true;
        assert!(valid_user_info_grant(&snapshot, "default", &grant));

        snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "client")
            .expect("configured client")
            .enabled = false;
        assert!(!valid_user_info_grant(&snapshot, "default", &grant));
        assert!(snapshot.configured_client("client").is_some());
    }

    #[actix_web::test]
    async fn invalidates_service_grants_when_the_active_policy_changes() {
        let base = application();
        let mut snapshot = (*base.snapshot()).clone();
        snapshot.configuration.issuers[0]
            .scopes
            .push("service.read".to_owned());
        snapshot
            .configuration
            .clients
            .push(crate::configuration::Client {
                enabled: true,
                issuer_ids: vec![],
                id: "service".to_owned(),
                name: "Service".to_owned(),
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
                secret_reference: Some(json!({"provider": "env", "key": "SERVICE_SECRET"})),
                jwks: None,
                branding: None,
            });
        let mut grant = crate::database::IntrospectionGrant {
            issuer: "https://id.example/default".to_owned(),
            subject: "service".to_owned(),
            client_id: "service".to_owned(),
            scopes: vec!["service.read".to_owned()],
            grant_type: "client_credentials".to_owned(),
            resource: Some("https://api.example/resource".to_owned()),
            dpop_jkt: None,
            auth_time: None,
            mfa_verified: false,
            authorization_details: Value::Array(vec![]),
            actor: None,
            expires_at: Utc::now() + Duration::minutes(5),
            issued_at: Utc::now(),
        };

        let issuing_client = snapshot.client("service").expect("service client");
        assert!(introspection_grant_visible_to_client(
            issuing_client,
            &grant
        ));
        let mut other_resource_server = issuing_client.clone();
        other_resource_server.id = "other-resource-server".to_owned();
        assert!(introspection_grant_visible_to_client(
            &other_resource_server,
            &grant
        ));
        grant.resource = None;
        assert!(introspection_grant_visible_to_client(
            issuing_client,
            &grant
        ));
        assert!(!introspection_grant_visible_to_client(
            &other_resource_server,
            &grant
        ));
        grant.resource = Some("https://api.example/resource".to_owned());

        assert!(active_introspection_grant(
            &snapshot,
            snapshot.issuer("default").expect("issuer"),
            &grant
        ));
        grant.authorization_details =
            json!([{"type": "account_information", "actions": ["read_balances"]}]);
        assert!(!active_introspection_grant(
            &snapshot,
            snapshot.issuer("default").expect("issuer"),
            &grant
        ));
        snapshot.configuration.authorization_detail_types.push(
            crate::configuration::AuthorizationDetailType {
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
            .find(|client| client.id == "service")
            .expect("service client")
            .authorization_details_types = vec!["account_information".to_owned()];
        assert!(active_introspection_grant(
            &snapshot,
            snapshot.issuer("default").expect("issuer"),
            &grant
        ));
        snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "service")
            .expect("service client")
            .resources
            .clear();
        assert!(!active_introspection_grant(
            &snapshot,
            snapshot.issuer("default").expect("issuer"),
            &grant
        ));
        snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "service")
            .expect("service client")
            .resources
            .push("https://api.example/resource".to_owned());
        snapshot
            .configuration
            .clients
            .iter_mut()
            .find(|client| client.id == "service")
            .expect("service client")
            .grant_types
            .clear();
        assert!(!active_introspection_grant(
            &snapshot,
            snapshot.issuer("default").expect("issuer"),
            &grant
        ));
    }

    #[actix_web::test]
    async fn validates_token_exchange_subjects_against_current_policy() {
        let base = application();
        let mut snapshot = (*base.snapshot()).clone();
        snapshot.configuration.issuers[0]
            .scopes
            .push("service.read".to_owned());
        snapshot
            .configuration
            .clients
            .push(crate::configuration::Client {
                enabled: true,
                issuer_ids: vec![],
                id: "broker".to_owned(),
                name: "Broker".to_owned(),
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
                grant_types: vec![
                    "client_credentials".to_owned(),
                    TOKEN_EXCHANGE_GRANT.to_owned(),
                ],
                pkce_required: None,
                nonce_required: None,
                consent_required: None,
                introspection_allowed: true,
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
                secret_reference: Some(json!({"provider": "env", "key": "BROKER_SECRET"})),
                jwks: None,
                branding: None,
            });
        let issuer = snapshot.issuer("default").expect("issuer");
        let client = snapshot.client("broker").expect("client");
        let mut subject = AccessGrant {
            issuer: issuer.url.clone(),
            subject: client.id.clone(),
            client_id: client.id.clone(),
            scopes: vec!["service.read".to_owned()],
            grant_type: "client_credentials".to_owned(),
            resource: Some("https://api.example/resource".to_owned()),
            dpop_jkt: None,
            auth_time: None,
            mfa_verified: false,
            claims: json!({}),
            authorization_details: Value::Array(vec![]),
            actor: None,
            expires_at: Utc::now() + Duration::minutes(5),
        };

        assert!(active_token_exchange_subject(
            &snapshot, issuer, client, &subject
        ));
        assert!(!active_token_exchange_actor(
            &snapshot, issuer, client, &subject
        ));
        snapshot
            .configuration
            .clients
            .last_mut()
            .expect("broker")
            .actor_token_exchange_allowed = true;
        let issuer = snapshot.issuer("default").expect("issuer");
        let client = snapshot.client("broker").expect("client");
        assert!(active_token_exchange_actor(
            &snapshot, issuer, client, &subject
        ));
        let first_actor = delegated_actor_claim("broker", None).expect("first actor");
        assert_eq!(first_actor, json!({"sub": "broker"}));
        let second_actor =
            delegated_actor_claim("downstream", Some(&first_actor)).expect("nested actor");
        assert_eq!(
            second_actor,
            json!({"sub": "downstream", "act": {"sub": "broker"}})
        );
        assert_eq!(actor_chain_depth(&second_actor), Some(2));
        assert_eq!(
            actor_chain_depth(&json!({"sub": "broker", "aud": "forbidden"})),
            None
        );
        let mut maximum_chain = first_actor.clone();
        for index in 1..MAX_ACTOR_CHAIN_DEPTH {
            maximum_chain =
                delegated_actor_claim(&format!("service-{index}"), Some(&maximum_chain))
                    .expect("bounded actor chain");
        }
        assert_eq!(
            actor_chain_depth(&maximum_chain),
            Some(MAX_ACTOR_CHAIN_DEPTH)
        );
        assert!(delegated_actor_claim("one-too-many", Some(&maximum_chain)).is_none());

        snapshot
            .configuration
            .users
            .push(crate::configuration::User {
                id: "delegated-user".to_owned(),
                identifier: "delegated@example.test".to_owned(),
                password_hash: "$2b$12$.JtidA6ZMWny4XaLMozDSOupYHbVNQurj8NkCdM9D3m/g3v3fyXXa"
                    .to_owned(),
                enabled: true,
                issuer_ids: vec![],
                totp_secret_reference: None,
                name: None,
                email: None,
                claims: Default::default(),
            });
        let delegated_subject_id = "delegated-user".to_owned();
        snapshot
            .configuration
            .clients
            .push(crate::configuration::Client {
                enabled: true,
                issuer_ids: vec![],
                id: "source-client".to_owned(),
                name: "Source client".to_owned(),
                client_type: "public".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier: None,
                redirect_uris: vec!["https://source.example/callback".to_owned()],
                post_logout_redirect_uris: vec![],
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                resources: vec![],
                scopes: vec!["openid".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
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
                authorized_actor_clients: vec!["broker".to_owned()],
                authorization_details_types: vec![],
                authentication_method: None,
                secret_reference: None,
                jwks: None,
                branding: None,
            });
        let delegated_subject = AccessGrant {
            issuer: snapshot.issuer("default").expect("issuer").url.clone(),
            subject: delegated_subject_id,
            client_id: "source-client".to_owned(),
            scopes: vec!["openid".to_owned()],
            grant_type: "authorization_code".to_owned(),
            resource: None,
            dpop_jkt: None,
            auth_time: Some(Utc::now().timestamp()),
            mfa_verified: false,
            claims: json!({}),
            authorization_details: Value::Array(vec![]),
            actor: None,
            expires_at: Utc::now() + Duration::minutes(5),
        };
        assert!(active_token_exchange_subject(
            &snapshot,
            snapshot.issuer("default").expect("issuer"),
            snapshot.client("broker").expect("broker"),
            &delegated_subject
        ));
        snapshot
            .configuration
            .clients
            .last_mut()
            .expect("source client")
            .authorized_actor_clients
            .clear();
        assert!(!active_token_exchange_subject(
            &snapshot,
            snapshot.issuer("default").expect("issuer"),
            snapshot.client("broker").expect("broker"),
            &delegated_subject
        ));
        snapshot.configuration.clients.pop();
        let issuer = snapshot.issuer("default").expect("issuer");
        let client = snapshot.client("broker").expect("client");
        subject.resource = Some("https://unregistered.example/resource".to_owned());
        assert!(!active_token_exchange_subject(
            &snapshot, issuer, client, &subject
        ));
        subject.resource = Some("https://api.example/resource".to_owned());
        subject.grant_type = TOKEN_EXCHANGE_GRANT.to_owned();
        subject.actor = Some(second_actor);
        assert!(active_token_exchange_subject(
            &snapshot, issuer, client, &subject
        ));

        snapshot
            .configuration
            .clients
            .last_mut()
            .expect("broker")
            .actor_token_exchange_allowed = false;
        assert!(!active_token_exchange_subject(
            &snapshot,
            snapshot.issuer("default").expect("issuer"),
            snapshot.client("broker").expect("client"),
            &subject
        ));
        snapshot
            .configuration
            .clients
            .last_mut()
            .expect("broker")
            .actor_token_exchange_allowed = true;

        snapshot
            .configuration
            .clients
            .last_mut()
            .expect("broker")
            .grant_types
            .retain(|grant| grant != TOKEN_EXCHANGE_GRANT);
        assert!(!active_token_exchange_subject(
            &snapshot,
            snapshot.issuer("default").expect("issuer"),
            snapshot.client("broker").expect("client"),
            &subject
        ));
    }

    #[actix_web::test]
    async fn bounds_submitted_credentials_by_utf8_byte_length() {
        assert!(valid_submitted_identifier("a"));
        assert!(valid_submitted_identifier(&"é".repeat(160)));
        assert!(!valid_submitted_identifier(""));
        assert!(!valid_submitted_identifier(&"é".repeat(161)));

        assert!(valid_submitted_password(&"a".repeat(72)));
        assert!(!valid_submitted_password(""));
        assert!(!valid_submitted_password(&"a".repeat(73)));
        assert!(!valid_submitted_password(&"é".repeat(37)));
    }

    #[actix_web::test]
    async fn rejects_non_http_backchannel_logout_targets_before_network_access() {
        assert_eq!(
            post_backchannel_logout("file:///tmp/logout", "header.payload.signature")
                .expect_err("unsupported callback scheme"),
            "unsupported back-channel logout URI scheme"
        );
    }

    #[actix_web::test]
    async fn rejects_oversized_authorization_and_logout_queries_before_storage() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(application()))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!(
                    "/default/authorize?future_extension={}",
                    "a".repeat(MAX_AUTHORIZATION_QUERY_BYTES)
                ))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!(
                    "/default/logout?id_token_hint={}",
                    "a".repeat(MAX_LOGOUT_HINT_BYTES + 1)
                ))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = test::read_body(response).await;
        assert!(
            body.windows("exceed the supported length".len())
                .any(|value| value == b"exceed the supported length")
        );
    }
}
