use crate::{
    Application,
    protocol::{AuthorizationRequest, DiscoveryDocument},
};
use actix_web::{HttpRequest, HttpResponse, Responder, http::StatusCode, web};
use askama::Template;
use serde_json::json;

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
        .route("/{issuer_id}/authorize", web::get().to(authorize))
        .default_service(web::to(not_found));
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
    json_response(
        StatusCode::OK,
        json!({"status": "ready", "revision": application.snapshot().revision}),
    )
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
            Ok(client) => html_response(
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
                }
                .render(),
            ),
            Err(message) => protocol_error(branding, message),
        },
        Err(_) => protocol_error(
            branding,
            "The authorization request is incomplete or malformed",
        ),
    }
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
        Application::new(Snapshot {
            configuration: RootConfiguration {
                schema_version: 1,
                issuers: vec![Issuer {
                    id: "default".to_owned(),
                    url: "https://id.example/default".to_owned(),
                    scopes: vec!["openid".to_owned()],
                }],
                clients: vec![],
                branding: Branding::default(),
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
