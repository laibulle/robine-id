use base64::Engine as _;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use robine_id::{
    Application, Snapshot,
    database::{
        AccessGrant, Database, DeviceAuthorizationDecision, DeviceAuthorizationRequest, DevicePoll,
        RefreshGrant, RefreshRotation, RefreshTokenSelection,
    },
    protocol::{AuthorizationGrant, AuthorizationRequest},
    tokens::{self, IdTokenInput},
    web as robine_web,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};

#[tokio::test]
#[ignore = "requires the development PostgreSQL service"]
async fn persists_and_atomically_consumes_security_state() {
    let database = Database::from_env()
        .expect("valid database environment")
        .expect("DATABASE_URL and encryption secret");
    database.migrate().await.expect("migrations");
    assert_eq!(
        database
            .statement_timeout_milliseconds()
            .await
            .expect("connection statement timeout"),
        std::env::var("DATABASE_STATEMENT_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| (100..=30_000).contains(value))
            .unwrap_or_else(|| {
                if std::env::var_os("VERCEL").is_some() {
                    2_000
                } else {
                    5_000
                }
            })
    );
    let unique = format!("{}-{}", std::process::id(), Utc::now().timestamp_micros());
    let issuer = format!("https://id.example/{unique}");
    let subject = format!("subject-{unique}");
    let totp_payload = json!({"request": "bounded"});
    let totp_challenge = database
        .issue_totp_challenge(&issuer, &subject, "authorization", &totp_payload, 300)
        .await
        .expect("TOTP challenge");
    let stored_totp = database
        .totp_challenge(&totp_challenge, &issuer, "authorization")
        .await
        .expect("load TOTP challenge")
        .expect("stored TOTP challenge");
    assert_eq!(stored_totp.subject, subject);
    assert_eq!(stored_totp.purpose, "authorization");
    assert_eq!(stored_totp.payload, totp_payload);
    let totp_counter = Utc::now().timestamp() / 30;
    assert!(
        database
            .consume_totp_challenge(
                &totp_challenge,
                &issuer,
                &subject,
                "authorization",
                totp_counter,
            )
            .await
            .expect("consume first TOTP challenge")
    );
    assert!(
        database
            .totp_challenge(&totp_challenge, &issuer, "authorization")
            .await
            .expect("reload consumed TOTP challenge")
            .is_none()
    );
    let replayed_totp_challenge = database
        .issue_totp_challenge(&issuer, &subject, "device", &json!({}), 300)
        .await
        .expect("second TOTP challenge");
    assert!(
        !database
            .consume_totp_challenge(
                &replayed_totp_challenge,
                &issuer,
                &subject,
                "device",
                totp_counter,
            )
            .await
            .expect("reject replayed TOTP counter")
    );
    assert!(
        database
            .totp_challenge(&replayed_totp_challenge, &issuer, "device")
            .await
            .expect("reload replayed TOTP challenge")
            .is_none()
    );
    let assertion_expiry = Utc::now() + Duration::minutes(5);
    assert!(
        database
            .register_client_assertion(
                &issuer,
                "integration-client",
                "single-use-jti",
                assertion_expiry,
            )
            .await
            .expect("first client assertion")
    );
    assert!(
        !database
            .register_client_assertion(
                &issuer,
                "integration-client",
                "single-use-jti",
                assertion_expiry,
            )
            .await
            .expect("replayed client assertion")
    );
    assert!(
        database
            .register_request_object(
                &issuer,
                "integration-client",
                "single-use-request-jti",
                assertion_expiry,
            )
            .await
            .expect("first request object")
    );
    assert!(
        !database
            .register_request_object(
                &issuer,
                "integration-client",
                "single-use-request-jti",
                assertion_expiry,
            )
            .await
            .expect("replayed request object")
    );
    let dpop_jkt =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(unique.as_bytes()));
    assert!(
        database
            .register_dpop_proof(&dpop_jkt, "single-use-dpop-jti", assertion_expiry)
            .await
            .expect("first DPoP proof")
    );
    assert!(
        !database
            .register_dpop_proof(&dpop_jkt, "single-use-dpop-jti", assertion_expiry)
            .await
            .expect("replayed DPoP proof")
    );
    assert!(
        database
            .validate_or_issue_dpop_nonce(&issuer, "authorization_server", &dpop_jkt, None, 29,)
            .await
            .is_err()
    );
    let dpop_nonce = database
        .validate_or_issue_dpop_nonce(&issuer, "authorization_server", &dpop_jkt, None, 300)
        .await
        .expect("DPoP nonce challenge")
        .expect("new DPoP nonce");
    assert!(
        database
            .validate_or_issue_dpop_nonce(
                &issuer,
                "authorization_server",
                &dpop_jkt,
                Some(&dpop_nonce),
                300,
            )
            .await
            .expect("valid DPoP nonce")
            .is_none()
    );
    let replacement_nonce = database
        .validate_or_issue_dpop_nonce(
            &issuer,
            "authorization_server",
            &dpop_jkt,
            Some("mismatched-nonce"),
            300,
        )
        .await
        .expect("replacement DPoP nonce")
        .expect("new replacement nonce");
    assert_ne!(replacement_nonce, dpop_nonce);
    assert!(
        database
            .validate_or_issue_dpop_nonce(
                &issuer,
                "authorization_server",
                &dpop_jkt,
                Some(&dpop_nonce),
                300,
            )
            .await
            .expect("recent DPoP nonce window")
            .is_none()
    );
    for index in 0..4 {
        assert!(
            database
                .validate_or_issue_dpop_nonce(
                    &issuer,
                    "authorization_server",
                    &dpop_jkt,
                    Some(&format!("another-mismatched-nonce-{index}")),
                    300,
                )
                .await
                .expect("bounded DPoP nonce window")
                .is_some()
        );
    }
    assert!(
        database
            .validate_or_issue_dpop_nonce(
                &issuer,
                "authorization_server",
                &dpop_jkt,
                Some(&dpop_nonce),
                300,
            )
            .await
            .expect("pruned old DPoP nonce")
            .is_some()
    );
    let linked_session = database
        .start_session_details(&subject, 5, 300, false)
        .await
        .expect("linked browser session");
    let grant = AuthorizationGrant {
        issuer: issuer.clone(),
        subject: subject.clone(),
        client_id: "integration-client".to_owned(),
        redirect_uri: "https://app.example/callback".to_owned(),
        scopes: vec!["openid".to_owned()],
        nonce: Some("nonce".to_owned()),
        code_challenge: Some("a".repeat(43)),
        response_mode: Some("form_post.jwt".to_owned()),
        resource: Some("https://api.example/resource".to_owned()),
        dpop_jkt: Some(dpop_jkt.clone()),
        session_id: Some(linked_session.session_id.clone()),
        auth_time: Some(Utc::now().timestamp()),
        mfa_verified: false,
        claims: json!({"name": "Integration"}),
        authorization_details: json!([{
            "type": "account_information",
            "actions": ["read_balances"]
        }]),
        expires_at: Utc::now() + Duration::minutes(5),
    };

    let code = database
        .issue_authorization_code(&grant)
        .await
        .expect("authorization code");
    let consumed_code = database
        .consume_authorization_code(&code)
        .await
        .expect("consume code")
        .expect("stored code");
    assert_eq!(
        consumed_code.response_mode.as_deref(),
        Some("form_post.jwt")
    );
    assert_eq!(
        consumed_code.resource.as_deref(),
        Some("https://api.example/resource")
    );
    assert_eq!(consumed_code.dpop_jkt.as_deref(), Some(dpop_jkt.as_str()));
    assert_eq!(
        consumed_code.session_id.as_deref(),
        Some(linked_session.session_id.as_str())
    );
    assert_eq!(
        consumed_code.authorization_details,
        grant.authorization_details
    );
    assert!(
        database
            .consume_authorization_code(&code)
            .await
            .expect("replay code")
            .is_none()
    );
    let logout_targets = database
        .revoke_session_and_clients(&linked_session.token)
        .await
        .expect("revoke linked browser session");
    assert_eq!(logout_targets.len(), 1);
    assert_eq!(logout_targets[0].issuer, issuer);
    assert_eq!(logout_targets[0].client_id, "integration-client");
    assert_eq!(logout_targets[0].subject, subject);
    assert_eq!(logout_targets[0].session_id, linked_session.session_id);

    let pushed_request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "integration-client".to_owned(),
        redirect_uri: "https://app.example/callback".to_owned(),
        scope: "openid".to_owned(),
        state: "pushed-state".to_owned(),
        nonce: "pushed-nonce".to_owned(),
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
        dpop_jkt: Some(dpop_jkt.clone()),
    };
    assert!(
        database
            .issue_pushed_authorization(&issuer, "integration-client", &pushed_request, 9)
            .await
            .is_err()
    );
    let request_uri = database
        .issue_pushed_authorization(&issuer, "integration-client", &pushed_request, 90)
        .await
        .expect("pushed authorization");
    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    assert!(
        database
            .consume_pushed_authorization(&request_uri, &issuer, "other-client")
            .await
            .expect("wrong-client pushed authorization")
            .is_none()
    );
    let consumed_request = database
        .consume_pushed_authorization(&request_uri, &issuer, "integration-client")
        .await
        .expect("consume pushed authorization")
        .expect("stored pushed authorization");
    assert_eq!(consumed_request.state, "pushed-state");
    assert_eq!(
        consumed_request.dpop_jkt.as_deref(),
        Some(dpop_jkt.as_str())
    );
    assert!(
        database
            .consume_pushed_authorization(&request_uri, &issuer, "integration-client")
            .await
            .expect("replay pushed authorization")
            .is_none()
    );

    assert!(
        database
            .issue_browser_authorization(&issuer, &pushed_request, 59)
            .await
            .is_err()
    );
    let browser_transaction = database
        .issue_browser_authorization(&issuer, &pushed_request, 600)
        .await
        .expect("browser authorization transaction");
    assert_eq!(browser_transaction.len(), 43);
    assert!(
        database
            .consume_browser_authorization(&browser_transaction, "https://other.example/issuer")
            .await
            .expect("wrong issuer browser authorization")
            .is_none()
    );
    let resumed_request = database
        .consume_browser_authorization(&browser_transaction, &issuer)
        .await
        .expect("consume browser authorization")
        .expect("stored browser authorization");
    assert_eq!(resumed_request.state, "pushed-state");
    assert!(
        database
            .consume_browser_authorization(&browser_transaction, &issuer)
            .await
            .expect("replay browser authorization")
            .is_none()
    );

    let pending = database
        .issue_pending_authorization(
            &grant,
            "state",
            Some("fr-FR en"),
            Some(r#"{"id_token":{"email":{"essential":true}}}"#),
        )
        .await
        .expect("pending authorization");
    let consumed_pending = database
        .consume_pending_authorization(&pending)
        .await
        .expect("consume pending")
        .expect("stored pending authorization");
    assert_eq!(
        consumed_pending.response_mode.as_deref(),
        Some("form_post.jwt")
    );
    assert_eq!(consumed_pending.ui_locales.as_deref(), Some("fr-FR en"));
    assert_eq!(
        consumed_pending.requested_claims.as_deref(),
        Some(r#"{"id_token":{"email":{"essential":true}}}"#)
    );
    assert_eq!(
        consumed_pending.resource.as_deref(),
        Some("https://api.example/resource")
    );
    assert_eq!(
        consumed_pending.dpop_jkt.as_deref(),
        Some(dpop_jkt.as_str())
    );
    assert_eq!(
        consumed_pending.authorization_details,
        grant.authorization_details
    );
    assert!(
        database
            .consume_pending_authorization(&pending)
            .await
            .expect("replay pending")
            .is_none()
    );

    let logout = database
        .issue_logout_transaction(
            &issuer,
            Some("integration-client"),
            Some("https://client.example/signed-out"),
            Some("logout-state"),
            Some("fr en"),
        )
        .await
        .expect("issue logout transaction");
    let consumed_logout = database
        .consume_logout_transaction(&logout)
        .await
        .expect("consume logout transaction")
        .expect("stored logout transaction");
    assert_eq!(consumed_logout.issuer.as_deref(), Some(issuer.as_str()));
    assert_eq!(
        consumed_logout.client_id.as_deref(),
        Some("integration-client")
    );
    assert_eq!(
        consumed_logout.post_logout_redirect_uri.as_deref(),
        Some("https://client.example/signed-out")
    );
    assert_eq!(consumed_logout.state.as_deref(), Some("logout-state"));
    assert_eq!(consumed_logout.ui_locales.as_deref(), Some("fr en"));
    assert!(
        database
            .consume_logout_transaction(&logout)
            .await
            .expect("replay logout transaction")
            .is_none()
    );

    let (device_code, formatted_user_code) = database
        .issue_device_authorization(DeviceAuthorizationRequest {
            issuer: &issuer,
            client_id: "integration-client",
            scopes: &["openid".to_owned(), "profile".to_owned()],
            resource: Some("https://api.example/resource"),
            authorization_details: &json!([{"type": "account_information", "actions": ["read_balances"]}]),
            lifetime_seconds: 600,
            poll_interval_seconds: 5,
        })
        .await
        .expect("device authorization");
    assert_eq!(device_code.len(), 43);
    assert_eq!(formatted_user_code.len(), 9);
    assert!(matches!(
        database
            .poll_device_authorization(&device_code, &issuer, "integration-client")
            .await
            .expect("fast device poll"),
        DevicePoll::SlowDown
    ));
    let integration_pool =
        sqlx::PgPool::connect(&std::env::var("DATABASE_URL").expect("integration DATABASE_URL"))
            .await
            .expect("integration database pool");
    sqlx::query(
        "UPDATE device_authorizations
         SET last_polled_at = now() - interval '20 seconds'
         WHERE issuer = $1 AND client_id = $2",
    )
    .bind(&issuer)
    .bind("integration-client")
    .execute(&integration_pool)
    .await
    .expect("advance device polling window");
    assert!(matches!(
        database
            .poll_device_authorization(&device_code, &issuer, "integration-client")
            .await
            .expect("pending device poll"),
        DevicePoll::Pending
    ));
    let user_code = formatted_user_code.replace('-', "");
    let (device_transaction, stored_device) = database
        .begin_device_verification(&user_code, &issuer)
        .await
        .expect("begin device verification")
        .expect("device user code");
    assert_eq!(stored_device.client_id, "integration-client");
    assert_eq!(stored_device.scopes, ["openid", "profile"]);
    assert_eq!(
        stored_device.authorization_details,
        json!([{"type": "account_information", "actions": ["read_balances"]}])
    );
    assert!(
        database
            .decide_device_authorization(
                &device_transaction,
                DeviceAuthorizationDecision {
                    subject: &subject,
                    claims: &json!({"name": "Integration"}),
                    auth_time: Utc::now().timestamp(),
                    session_id: None,
                    approved: true,
                    mfa_verified: true,
                },
            )
            .await
            .expect("approve device")
    );
    match database
        .poll_device_authorization(&device_code, &issuer, "integration-client")
        .await
        .expect("approved device poll")
    {
        DevicePoll::Approved(grant) => {
            assert_eq!(grant.subject, subject);
            assert_eq!(grant.scopes, ["openid", "profile"]);
            assert_eq!(grant.claims, json!({"name": "Integration"}));
            assert_eq!(
                grant.authorization_details,
                json!([{"type": "account_information", "actions": ["read_balances"]}])
            );
            assert!(grant.mfa_verified);
        }
        poll => panic!("unexpected approved device poll: {poll:?}"),
    }
    assert!(matches!(
        database
            .poll_device_authorization(&device_code, &issuer, "integration-client")
            .await
            .expect("consumed device code"),
        DevicePoll::Invalid
    ));

    let (denied_device_code, denied_user_code) = database
        .issue_device_authorization(DeviceAuthorizationRequest {
            issuer: &issuer,
            client_id: "integration-client",
            scopes: &["openid".to_owned()],
            resource: None,
            authorization_details: &json!([]),
            lifetime_seconds: 600,
            poll_interval_seconds: 5,
        })
        .await
        .expect("denied device authorization");
    let (denied_transaction, _) = database
        .begin_device_verification(&denied_user_code.replace('-', ""), &issuer)
        .await
        .expect("begin denied device verification")
        .expect("denied device user code");
    assert!(
        database
            .decide_device_authorization(
                &denied_transaction,
                DeviceAuthorizationDecision {
                    subject: &subject,
                    claims: &json!({}),
                    auth_time: Utc::now().timestamp(),
                    session_id: None,
                    approved: false,
                    mfa_verified: false,
                },
            )
            .await
            .expect("deny device")
    );
    let denied_identity: (Option<String>, Option<i64>, serde_json::Value) = sqlx::query_as(
        "SELECT subject, auth_time, claims
         FROM device_authorizations
         WHERE issuer = $1 AND client_id = $2 AND status = 'denied'
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&issuer)
    .bind("integration-client")
    .fetch_one(&integration_pool)
    .await
    .expect("privacy-minimized denied device row");
    assert_eq!(denied_identity, (None, None, json!({})));
    assert!(matches!(
        database
            .poll_device_authorization(&denied_device_code, &issuer, "integration-client")
            .await
            .expect("denied device poll"),
        DevicePoll::Denied
    ));

    let access_token = database
        .issue_access_token(&AccessGrant {
            issuer: issuer.clone(),
            subject: subject.clone(),
            client_id: "integration-client".to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            grant_type: "authorization_code".to_owned(),
            resource: Some("https://api.example/resource".to_owned()),
            dpop_jkt: Some(dpop_jkt.clone()),
            auth_time: Some(Utc::now().timestamp()),
            mfa_verified: true,
            claims: json!({"name": "Integration"}),
            authorization_details: grant.authorization_details.clone(),
            actor: None,
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .await
        .expect("access token");
    let introspection = database
        .introspection_grant(&access_token, &issuer)
        .await
        .expect("introspection lookup")
        .expect("active introspection grant");
    assert_eq!(introspection.client_id, "integration-client");
    assert_eq!(introspection.grant_type, "authorization_code");
    assert_eq!(
        introspection.resource.as_deref(),
        Some("https://api.example/resource")
    );
    assert_eq!(introspection.dpop_jkt.as_deref(), Some(dpop_jkt.as_str()));
    assert!(introspection.auth_time.is_some());
    assert!(introspection.mfa_verified);
    assert_eq!(
        introspection.authorization_details,
        grant.authorization_details
    );
    assert!(introspection.expires_at > Utc::now());
    assert!(
        !database
            .revoke_access_token(&access_token, &issuer, "other-client")
            .await
            .expect("wrong-client revocation")
    );
    assert!(
        database
            .revoke_access_token(&access_token, &issuer, "integration-client")
            .await
            .expect("bound revocation")
    );
    assert!(
        database
            .introspection_grant(&access_token, &issuer)
            .await
            .expect("revoked introspection lookup")
            .is_none()
    );

    let exchanged_access_token = database
        .issue_access_token(&AccessGrant {
            issuer: issuer.clone(),
            subject: subject.clone(),
            client_id: "integration-client".to_owned(),
            scopes: vec!["profile".to_owned()],
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_owned(),
            resource: Some("https://api.example/exchanged".to_owned()),
            dpop_jkt: Some(dpop_jkt.clone()),
            auth_time: Some(Utc::now().timestamp()),
            mfa_verified: true,
            claims: json!({"name": "Integration"}),
            authorization_details: json!([]),
            actor: Some(json!({"sub": "integration-client"})),
            expires_at: Utc::now() + Duration::minutes(4),
        })
        .await
        .expect("exchanged access token");
    let exchanged_introspection = database
        .introspection_grant(&exchanged_access_token, &issuer)
        .await
        .expect("exchanged token introspection lookup")
        .expect("active exchanged token");
    assert_eq!(
        exchanged_introspection.grant_type,
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
    assert_eq!(exchanged_introspection.scopes, ["profile"]);
    assert_eq!(
        exchanged_introspection.resource.as_deref(),
        Some("https://api.example/exchanged")
    );
    assert!(exchanged_introspection.auth_time.is_some());
    assert!(exchanged_introspection.mfa_verified);
    assert_eq!(
        exchanged_introspection.actor,
        Some(json!({"sub": "integration-client"}))
    );

    let device_access_token = database
        .issue_access_token(&AccessGrant {
            issuer: issuer.clone(),
            subject: subject.clone(),
            client_id: "integration-client".to_owned(),
            scopes: vec!["openid".to_owned()],
            grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
            resource: None,
            dpop_jkt: None,
            auth_time: Some(Utc::now().timestamp()),
            mfa_verified: false,
            claims: json!({}),
            authorization_details: json!([]),
            actor: None,
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .await
        .expect("device access token");
    let device_introspection = database
        .introspection_grant(&device_access_token, &issuer)
        .await
        .expect("device token introspection")
        .expect("active device token");
    assert_eq!(
        device_introspection.grant_type,
        "urn:ietf:params:oauth:grant-type:device_code"
    );
    assert!(device_introspection.auth_time.is_some());
    assert!(!device_introspection.mfa_verified);

    let refresh_grant = RefreshGrant {
        issuer: issuer.clone(),
        subject: subject.clone(),
        client_id: "integration-client".to_owned(),
        scopes: vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "offline_access".to_owned(),
        ],
        resource: Some("https://api.example/resource".to_owned()),
        dpop_jkt: Some(dpop_jkt.clone()),
        session_id: None,
        auth_time: Some(Utc::now().timestamp()),
        mfa_verified: false,
        claims: json!({"name": "Integration"}),
        authorization_details: grant.authorization_details.clone(),
        expires_at: Utc::now() + Duration::days(30),
    };
    let refresh_token = database
        .issue_refresh_token(&refresh_grant)
        .await
        .expect("refresh token");
    assert!(matches!(
        database
            .rotate_refresh_token(
                &refresh_token,
                &issuer,
                "integration-client",
                RefreshTokenSelection {
                    resource: Some("https://other-api.example/resource"),
                    dpop_jkt: Some(&dpop_jkt),
                    ..Default::default()
                },
            )
            .await
            .expect("invalid resource"),
        RefreshRotation::InvalidTarget
    ));
    assert!(matches!(
        database
            .rotate_refresh_token(
                &refresh_token,
                &issuer,
                "integration-client",
                RefreshTokenSelection::default(),
            )
            .await
            .expect("missing DPoP proof"),
        RefreshRotation::InvalidDpopProof
    ));
    let excessive_authorization_details = json!([{
        "type": "account_information",
        "actions": ["initiate_payment"]
    }]);
    assert!(matches!(
        database
            .rotate_refresh_token(
                &refresh_token,
                &issuer,
                "integration-client",
                RefreshTokenSelection {
                    authorization_details: Some(&excessive_authorization_details),
                    dpop_jkt: Some(&dpop_jkt),
                    ..Default::default()
                },
            )
            .await
            .expect("excessive authorization details"),
        RefreshRotation::InvalidAuthorizationDetails
    ));
    let selected_authorization_details = grant.authorization_details.clone();
    let rotated_token = match database
        .rotate_refresh_token(
            &refresh_token,
            &issuer,
            "integration-client",
            RefreshTokenSelection {
                scopes: Some(&["openid".to_owned(), "offline_access".to_owned()]),
                authorization_details: Some(&selected_authorization_details),
                dpop_jkt: Some(&dpop_jkt),
                ..Default::default()
            },
        )
        .await
        .expect("refresh rotation")
    {
        RefreshRotation::Rotated { token, grant } => {
            assert_eq!(grant.scopes, ["openid", "offline_access"]);
            assert_eq!(grant.resource, refresh_grant.resource);
            assert_eq!(grant.dpop_jkt, refresh_grant.dpop_jkt);
            assert_eq!(grant.authorization_details, selected_authorization_details);
            token
        }
        rotation => panic!("unexpected rotation: {rotation:?}"),
    };
    assert!(matches!(
        database
            .rotate_refresh_token(
                &refresh_token,
                &issuer,
                "integration-client",
                RefreshTokenSelection::default(),
            )
            .await
            .expect("missing proof on consumed DPoP refresh token"),
        RefreshRotation::InvalidDpopProof
    ));
    assert!(matches!(
        database
            .rotate_refresh_token(
                &refresh_token,
                &issuer,
                "integration-client",
                RefreshTokenSelection {
                    dpop_jkt: Some(&dpop_jkt),
                    ..Default::default()
                },
            )
            .await
            .expect("replay detection"),
        RefreshRotation::Replayed
    ));
    assert!(matches!(
        database
            .rotate_refresh_token(
                &rotated_token,
                &issuer,
                "integration-client",
                RefreshTokenSelection {
                    dpop_jkt: Some(&dpop_jkt),
                    ..Default::default()
                },
            )
            .await
            .expect("revoked family"),
        RefreshRotation::Invalid
    ));

    let scoped_refresh = database
        .issue_refresh_token(&refresh_grant)
        .await
        .expect("scoped refresh token");
    assert!(matches!(
        database
            .rotate_refresh_token(
                &scoped_refresh,
                &issuer,
                "integration-client",
                RefreshTokenSelection {
                    scopes: Some(&["openid".to_owned(), "ungranted".to_owned()]),
                    dpop_jkt: Some(&dpop_jkt),
                    ..Default::default()
                },
            )
            .await
            .expect("invalid scope"),
        RefreshRotation::InvalidScope
    ));
    let scoped_rotation = database
        .rotate_refresh_token(
            &scoped_refresh,
            &issuer,
            "integration-client",
            RefreshTokenSelection {
                dpop_jkt: Some(&dpop_jkt),
                ..Default::default()
            },
        )
        .await
        .expect("valid rotation after rejected scope");
    let RefreshRotation::Rotated {
        token: scoped_rotated,
        ..
    } = scoped_rotation
    else {
        panic!("valid scope did not rotate")
    };
    assert!(
        !database
            .revoke_refresh_token(&scoped_rotated, &issuer, "other-client")
            .await
            .expect("wrong-client refresh revocation")
    );
    assert!(
        database
            .revoke_refresh_token(&scoped_rotated, &issuer, "integration-client")
            .await
            .expect("refresh revocation")
    );
    assert!(matches!(
        database
            .rotate_refresh_token(
                &scoped_rotated,
                &issuer,
                "integration-client",
                RefreshTokenSelection {
                    dpop_jkt: Some(&dpop_jkt),
                    ..Default::default()
                },
            )
            .await
            .expect("revoked refresh token"),
        RefreshRotation::Invalid
    ));

    let first = database
        .start_session(&subject, 2, 300, false)
        .await
        .expect("first session");
    let second = database
        .start_session(&subject, 2, 300, true)
        .await
        .expect("second session");
    let third = database
        .start_session(&subject, 2, 300, false)
        .await
        .expect("third session");
    assert!(
        database
            .validate_session_details(&second, 300)
            .await
            .expect("validate MFA session")
            .is_some_and(|session| session.mfa_verified)
    );
    assert!(
        database
            .validate_session(&first, 300)
            .await
            .expect("validate oldest")
            .is_none()
    );
    assert!(
        database
            .validate_session(&second, 300)
            .await
            .expect("validate second")
            .is_some()
    );
    assert!(
        database
            .validate_session(&third, 300)
            .await
            .expect("validate newest")
            .is_some()
    );

    let concurrent_subject = format!("concurrent-{unique}");
    let first_database = database.clone();
    let second_database = database.clone();
    let (first_concurrent, second_concurrent) = tokio::join!(
        first_database.start_session(&concurrent_subject, 1, 300, false),
        second_database.start_session(&concurrent_subject, 1, 300, false)
    );
    let first_concurrent = first_concurrent.expect("first concurrent session");
    let second_concurrent = second_concurrent.expect("second concurrent session");
    let first_retained = database
        .validate_session(&first_concurrent, 300)
        .await
        .expect("validate first concurrent session")
        .is_some();
    let second_retained = database
        .validate_session(&second_concurrent, 300)
        .await
        .expect("validate second concurrent session")
        .is_some();
    assert_eq!(
        usize::from(first_retained) + usize::from(second_retained),
        1
    );

    assert!(
        database
            .allow_authentication_attempt(&unique, 2, 60)
            .await
            .expect("rate attempt one")
    );
    assert!(
        database
            .allow_authentication_attempt(&unique, 2, 60)
            .await
            .expect("rate attempt two")
    );
    assert!(
        !database
            .allow_authentication_attempt(&unique, 2, 60)
            .await
            .expect("rate attempt three")
    );
    let independent_rate_keys = vec![format!("{unique}-network"), format!("{unique}-identifier")];
    assert!(
        database
            .allow_authentication_attempts(&independent_rate_keys, 2, 60)
            .await
            .expect("multi-dimensional rate attempt one")
    );
    assert!(
        database
            .allow_authentication_attempts(&independent_rate_keys, 2, 60)
            .await
            .expect("multi-dimensional rate attempt two")
    );
    assert!(
        !database
            .allow_authentication_attempts(&independent_rate_keys, 2, 60)
            .await
            .expect("multi-dimensional rate attempt three")
    );
    assert!(
        !database
            .allow_authentication_attempt(&independent_rate_keys[1], 2, 60)
            .await
            .expect("identifier dimension remains exhausted")
    );

    database
        .prune_retained_signing_keys()
        .await
        .expect("normalize expired retained keys");
    let initial = database.signing_key(&issuer).await.expect("initial key");
    let (rotated, changed) = database
        .rotate_signing_key(&issuer, "integration-rotation", 600)
        .await
        .expect("key rotation");
    let (unchanged, changed_again) = database
        .rotate_signing_key(&issuer, "integration-rotation", 600)
        .await
        .expect("idempotent rotation");
    assert!(changed);
    assert!(!changed_again);
    assert_ne!(initial.kid, rotated.kid);
    assert_eq!(rotated.kid, unchanged.kid);
    assert_eq!(
        database
            .public_signing_keys(&issuer)
            .await
            .expect("public keys")
            .len(),
        2
    );
    assert_eq!(
        database
            .prune_retained_signing_keys()
            .await
            .expect("unexpired retained key pruning"),
        0
    );
    let inspection_pool =
        sqlx::PgPool::connect(&std::env::var("DATABASE_URL").expect("integration DATABASE_URL"))
            .await
            .expect("inspection pool");
    let retention_is_future: bool = sqlx::query_scalar(
        "SELECT bool_and(retain_until > retired_at)
         FROM retained_signing_keys WHERE issuer = $1",
    )
    .bind(&issuer)
    .fetch_one(&inspection_pool)
    .await
    .expect("retention deadline");
    assert!(retention_is_future);
    sqlx::query(
        "UPDATE retained_signing_keys SET retain_until = now() - interval '1 second'
         WHERE issuer = $1",
    )
    .bind(&issuer)
    .execute(&inspection_pool)
    .await
    .expect("expire retained key");
    assert_eq!(
        database
            .prune_retained_signing_keys()
            .await
            .expect("expired retained key pruning"),
        1
    );
    assert_eq!(
        database
            .public_signing_keys(&issuer)
            .await
            .expect("public keys after pruning")
            .len(),
        1
    );
    let (not_due, changed_early) = database
        .rotate_signing_key_if_due(&issuer, 3_600, 600, chrono::Utc::now())
        .await
        .expect("automatic rotation remains inside interval");
    assert!(!changed_early);
    let automatic_rotation_time = chrono::Utc::now() + chrono::Duration::seconds(3_601);
    let (automatically_rotated, changed_automatically) = database
        .rotate_signing_key_if_due(&issuer, 3_600, 600, automatic_rotation_time)
        .await
        .expect("due automatic rotation");
    let (automatic_retry, changed_on_retry) = database
        .rotate_signing_key_if_due(&issuer, 3_600, 600, automatic_rotation_time)
        .await
        .expect("idempotent automatic rotation retry");
    assert!(changed_automatically);
    assert!(!changed_on_retry);
    assert_ne!(not_due.kid, automatically_rotated.kid);
    assert_eq!(automatically_rotated.kid, automatic_retry.kid);
    assert_eq!(
        database
            .public_signing_keys(&issuer)
            .await
            .expect("automatic rotation publishes retained and active keys")
            .len(),
        2
    );

    let sso_session = database
        .start_session("development-user", 5, 300, false)
        .await
        .expect("SSO session");
    let mut snapshot = Snapshot::load().expect("configuration");
    snapshot.configuration.issuers[0]
        .token_policy
        .pushed_authorization_request_limit = 1;
    snapshot.configuration.issuers[0]
        .token_policy
        .access_token_format = "jwt".to_owned();
    let par_client_id = format!("par-{unique}");
    let mut par_client = snapshot
        .client("rust-development-client")
        .expect("development public client")
        .clone();
    par_client.id = par_client_id.clone();
    par_client.name = "Integration PAR client".to_owned();
    snapshot.configuration.clients.push(par_client);
    snapshot.configuration.issuers[0]
        .scopes
        .push("service.read".to_owned());
    snapshot.configuration.issuers[0]
        .scopes
        .push("offline_access".to_owned());
    let device_client_id = format!("device-{unique}");
    snapshot
        .configuration
        .clients
        .push(robine_id::configuration::Client {
            enabled: true,
            issuer_ids: vec![],
            id: device_client_id.clone(),
            name: "Integration device client".to_owned(),
            client_type: "public".to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier: None,
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            resources: vec![],
            scopes: vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
                "offline_access".to_owned(),
            ],
            grant_types: vec![
                "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
                "refresh_token".to_owned(),
            ],
            pkce_required: None,
            nonce_required: None,
            consent_required: Some(true),
            introspection_allowed: false,
            userinfo_signed_response_alg: Some("RS256".to_owned()),
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
        });
    let service_client_id = format!("service-{unique}");
    snapshot
        .configuration
        .clients
        .push(robine_id::configuration::Client {
            enabled: true,
            issuer_ids: vec![],
            id: service_client_id.clone(),
            name: "Integration service client".to_owned(),
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
            secret_reference: Some(json!({
                "provider": "env",
                "key": "KEY_ENCRYPTION_SECRET"
            })),
            jwks: None,
            branding: None,
        });
    let web_issuer = snapshot
        .issuer("default")
        .expect("default issuer")
        .url
        .trim_end_matches('/')
        .to_owned();
    let application = Application::new(snapshot).expect("valid application environment");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(actix_web::web::Data::new(application.clone()))
            .configure(robine_web::configure),
    )
    .await;
    let service_secret = std::env::var("KEY_ENCRYPTION_SECRET").expect("integration secret");
    let service_basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{service_client_id}:{service_secret}"))
    );
    let discovery_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/default/.well-known/openid-configuration")
            .to_request(),
    )
    .await;
    let discovery: serde_json::Value = actix_web::test::read_body_json(discovery_response).await;
    assert!(
        discovery["grant_types_supported"]
            .as_array()
            .expect("grant types")
            .contains(&json!("client_credentials"))
    );
    assert!(
        discovery["grant_types_supported"]
            .as_array()
            .expect("grant types")
            .contains(&json!("urn:ietf:params:oauth:grant-type:device_code"))
    );
    assert_eq!(
        discovery["device_authorization_endpoint"],
        format!("{web_issuer}/device_authorization")
    );
    assert_eq!(
        discovery["access_token_signing_alg_values_supported"],
        json!(["RS256"])
    );

    let default_device_scope_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/device_authorization")
            .set_form([("client_id", device_client_id.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(
        default_device_scope_response.status(),
        actix_web::http::StatusCode::OK
    );
    let default_device_scope: serde_json::Value =
        actix_web::test::read_body_json(default_device_scope_response).await;
    let default_user_code = default_device_scope["user_code"]
        .as_str()
        .expect("default-scope user code")
        .replace('-', "");
    let (default_scope_transaction, default_scope_authorization) = database
        .begin_device_verification(&default_user_code, &web_issuer)
        .await
        .expect("default-scope device verification")
        .expect("default-scope device authorization");
    assert_eq!(
        default_scope_authorization.scopes,
        ["openid", "profile", "email"]
    );
    assert!(
        !default_scope_authorization
            .scopes
            .contains(&"offline_access".to_owned())
    );
    assert!(
        database
            .decide_device_authorization(
                &default_scope_transaction,
                DeviceAuthorizationDecision {
                    subject: "release-smoke-user",
                    claims: &json!({}),
                    auth_time: Utc::now().timestamp(),
                    session_id: None,
                    approved: false,
                    mfa_verified: false,
                },
            )
            .await
            .expect("discard default-scope device authorization")
    );

    let device_authorization_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/device_authorization")
            .set_form([
                ("client_id", device_client_id.as_str()),
                ("scope", "openid profile email offline_access"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        device_authorization_response.status(),
        actix_web::http::StatusCode::OK
    );
    assert_eq!(
        device_authorization_response
            .headers()
            .get(actix_web::http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let device_authorization: serde_json::Value =
        actix_web::test::read_body_json(device_authorization_response).await;
    let web_device_code = device_authorization["device_code"]
        .as_str()
        .expect("device code")
        .to_owned();
    let web_user_code = device_authorization["user_code"]
        .as_str()
        .expect("user code")
        .to_owned();
    assert_eq!(device_authorization["interval"], 5);
    assert_eq!(
        device_authorization["verification_uri"],
        format!("{web_issuer}/device")
    );
    assert!(
        device_authorization["verification_uri_complete"]
            .as_str()
            .is_some_and(|uri| uri.contains("user_code="))
    );

    let fast_device_poll = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/token")
            .set_form([
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", web_device_code.as_str()),
                ("client_id", device_client_id.as_str()),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        fast_device_poll.status(),
        actix_web::http::StatusCode::BAD_REQUEST
    );
    let fast_device_poll_body: serde_json::Value =
        actix_web::test::read_body_json(fast_device_poll).await;
    assert_eq!(fast_device_poll_body["error"], "slow_down");

    let device_code_page = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/device?user_code={web_user_code}"))
            .to_request(),
    )
    .await;
    assert_eq!(device_code_page.status(), actix_web::http::StatusCode::OK);
    let device_code_csrf = device_code_page
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "robine_csrf")
        .expect("device code CSRF cookie")
        .value()
        .to_owned();
    let device_code_html = actix_web::test::read_body(device_code_page).await;
    assert!(
        std::str::from_utf8(&device_code_html)
            .expect("device page UTF-8")
            .contains(&web_user_code)
    );

    let device_confirmation = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/device")
            .cookie(actix_web::cookie::Cookie::new(
                "robine_csrf",
                device_code_csrf.clone(),
            ))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .set_form([
                ("action", "verify"),
                ("csrf_token", device_code_csrf.as_str()),
                ("user_code", web_user_code.as_str()),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        device_confirmation.status(),
        actix_web::http::StatusCode::OK
    );
    let confirmation_csrf = device_confirmation
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "robine_csrf")
        .expect("device confirmation CSRF cookie")
        .value()
        .to_owned();
    let confirmation_html = actix_web::test::read_body(device_confirmation).await;
    let confirmation_html =
        std::str::from_utf8(&confirmation_html).expect("device confirmation UTF-8");
    let device_transaction = hidden_form_value(confirmation_html, "transaction");
    assert!(confirmation_html.contains("id=\"device-approve\""));
    assert!(!confirmation_html.contains("id=\"device_password\""));

    let device_approval = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/device")
            .cookie(actix_web::cookie::Cookie::new(
                "robine_csrf",
                confirmation_csrf.clone(),
            ))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .set_form([
                ("action", "decision"),
                ("csrf_token", confirmation_csrf.as_str()),
                ("transaction", device_transaction.as_str()),
                ("user_code", web_user_code.as_str()),
                ("decision", "approve"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(device_approval.status(), actix_web::http::StatusCode::OK);
    let device_approval_html = actix_web::test::read_body(device_approval).await;
    assert!(
        std::str::from_utf8(&device_approval_html)
            .expect("device approval UTF-8")
            .contains("id=\"device-done-title\"")
    );

    let successful_device_poll = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/token")
            .set_form([
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", web_device_code.as_str()),
                ("client_id", device_client_id.as_str()),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        successful_device_poll.status(),
        actix_web::http::StatusCode::OK
    );
    let successful_device_body: serde_json::Value =
        actix_web::test::read_body_json(successful_device_poll).await;
    assert_eq!(successful_device_body["token_type"], "Bearer");
    assert_eq!(
        successful_device_body["scope"],
        "openid profile email offline_access"
    );
    assert!(successful_device_body["id_token"].is_string());
    assert!(successful_device_body["refresh_token"].is_string());
    let web_device_access_token = successful_device_body["access_token"]
        .as_str()
        .expect("device access token");
    assert_eq!(web_device_access_token.split('.').count(), 3);
    let device_userinfo = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/default/userinfo")
            .insert_header((
                actix_web::http::header::AUTHORIZATION,
                format!("Bearer {web_device_access_token}"),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(device_userinfo.status(), actix_web::http::StatusCode::OK);
    assert_eq!(
        device_userinfo
            .headers()
            .get(actix_web::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/jwt")
    );
    let signed_device_userinfo = actix_web::test::read_body(device_userinfo).await;
    let signed_device_userinfo =
        std::str::from_utf8(&signed_device_userinfo).expect("signed UserInfo UTF-8");
    let userinfo_header = decode_header(signed_device_userinfo).expect("signed UserInfo header");
    let userinfo_key = database
        .public_signing_keys(&web_issuer)
        .await
        .expect("UserInfo public signing keys")
        .into_iter()
        .find(|key| Some(key.kid.as_str()) == userinfo_header.kid.as_deref())
        .expect("UserInfo signing key is published");
    let mut userinfo_validation = Validation::new(Algorithm::RS256);
    userinfo_validation.set_issuer(&[web_issuer.as_str()]);
    userinfo_validation.set_audience(&[device_client_id.as_str()]);
    let device_userinfo_body = decode::<serde_json::Value>(
        signed_device_userinfo,
        &DecodingKey::from_rsa_components(&userinfo_key.modulus, &userinfo_key.exponent)
            .expect("UserInfo decoding key"),
        &userinfo_validation,
    )
    .expect("valid signed UserInfo response")
    .claims;
    assert_eq!(device_userinfo_body["sub"], "development-user");
    assert_eq!(device_userinfo_body["email"], "admin@example.com");
    let device_userinfo_post = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/userinfo")
            .insert_header((
                actix_web::http::header::AUTHORIZATION,
                format!("Bearer {web_device_access_token}"),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        device_userinfo_post.status(),
        actix_web::http::StatusCode::OK
    );
    assert_eq!(
        device_userinfo_post
            .headers()
            .get(actix_web::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/jwt")
    );
    let signed_device_userinfo_post = actix_web::test::read_body(device_userinfo_post).await;
    let signed_device_userinfo_post =
        std::str::from_utf8(&signed_device_userinfo_post).expect("signed POST UserInfo UTF-8");
    let post_userinfo_body = decode::<serde_json::Value>(
        signed_device_userinfo_post,
        &DecodingKey::from_rsa_components(&userinfo_key.modulus, &userinfo_key.exponent)
            .expect("POST UserInfo decoding key"),
        &userinfo_validation,
    )
    .expect("valid signed POST UserInfo response")
    .claims;
    assert_eq!(post_userinfo_body["sub"], "development-user");
    let invalid_service_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/token")
            .insert_header((
                actix_web::http::header::AUTHORIZATION,
                service_basic.clone(),
            ))
            .set_form([("grant_type", "client_credentials"), ("scope", "openid")])
            .to_request(),
    )
    .await;
    assert_eq!(
        invalid_service_response.status(),
        actix_web::http::StatusCode::BAD_REQUEST
    );
    let invalid_service_body: serde_json::Value =
        actix_web::test::read_body_json(invalid_service_response).await;
    assert_eq!(invalid_service_body["error"], "invalid_scope");
    let service_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/token")
            .insert_header((
                actix_web::http::header::AUTHORIZATION,
                service_basic.clone(),
            ))
            .set_form([
                ("grant_type", "client_credentials"),
                ("scope", "service.read"),
                ("resource", "https://api.example/resource"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(service_response.status(), actix_web::http::StatusCode::OK);
    let service_body: serde_json::Value = actix_web::test::read_body_json(service_response).await;
    assert_eq!(service_body["token_type"], "Bearer");
    assert_eq!(service_body["scope"], "service.read");
    assert!(service_body.get("id_token").is_none());
    assert!(service_body.get("refresh_token").is_none());
    let service_token = service_body["access_token"]
        .as_str()
        .expect("service access token");
    assert_eq!(service_token.split('.').count(), 3);
    let service_header = decode_header(service_token).expect("JWT access token header");
    assert_eq!(service_header.typ.as_deref(), Some("at+jwt"));
    let service_key = database
        .public_signing_keys(&web_issuer)
        .await
        .expect("published signing keys")
        .into_iter()
        .find(|key| Some(key.kid.as_str()) == service_header.kid.as_deref())
        .expect("access token signing key");
    let mut service_validation = Validation::new(Algorithm::RS256);
    service_validation.set_issuer(&[web_issuer.as_str()]);
    service_validation.set_audience(&["https://api.example/resource"]);
    let decoded_service = decode::<serde_json::Value>(
        service_token,
        &DecodingKey::from_rsa_components(&service_key.modulus, &service_key.exponent)
            .expect("published RSA key"),
        &service_validation,
    )
    .expect("offline-verifiable access token");
    assert_eq!(decoded_service.claims["sub"], service_client_id);
    assert_eq!(decoded_service.claims["client_id"], service_client_id);
    assert_eq!(decoded_service.claims["scope"], "service.read");
    assert!(decoded_service.claims["jti"].is_string());
    assert!(decoded_service.claims.get("cnf").is_none());
    let service_introspection = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/introspect")
            .insert_header((
                actix_web::http::header::AUTHORIZATION,
                service_basic.clone(),
            ))
            .set_form([("token", service_token)])
            .to_request(),
    )
    .await;
    let service_introspection_body: serde_json::Value =
        actix_web::test::read_body_json(service_introspection).await;
    assert_eq!(service_introspection_body["active"], true);
    assert_eq!(service_introspection_body["client_id"], service_client_id);
    assert_eq!(service_introspection_body["sub"], service_client_id);
    assert_eq!(service_introspection_body["scope"], "service.read");
    let signed_service_introspection = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/introspect")
            .insert_header((
                actix_web::http::header::AUTHORIZATION,
                service_basic.clone(),
            ))
            .insert_header((
                actix_web::http::header::ACCEPT,
                "application/token-introspection+jwt",
            ))
            .set_form([("token", service_token)])
            .to_request(),
    )
    .await;
    assert_eq!(
        signed_service_introspection.status(),
        actix_web::http::StatusCode::OK
    );
    assert_eq!(
        signed_service_introspection
            .headers()
            .get(actix_web::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/token-introspection+jwt")
    );
    let signed_service_introspection =
        actix_web::test::read_body(signed_service_introspection).await;
    let signed_service_introspection =
        std::str::from_utf8(&signed_service_introspection).expect("compact introspection JWT");
    let signed_header =
        decode_header(signed_service_introspection).expect("signed introspection header");
    assert_eq!(
        signed_header.typ.as_deref(),
        Some("token-introspection+jwt")
    );
    let signing_key = database
        .public_signing_keys(&web_issuer)
        .await
        .expect("introspection response signing keys")
        .into_iter()
        .find(|key| Some(key.kid.as_str()) == signed_header.kid.as_deref())
        .expect("introspection response signing key");
    let mut signed_validation = Validation::new(Algorithm::RS256);
    signed_validation.required_spec_claims.clear();
    signed_validation.validate_exp = false;
    signed_validation.set_issuer(&[web_issuer.as_str()]);
    signed_validation.set_audience(&[service_client_id.as_str()]);
    let signed_introspection = decode::<serde_json::Value>(
        signed_service_introspection,
        &DecodingKey::from_rsa_components(&signing_key.modulus, &signing_key.exponent)
            .expect("introspection response public key"),
        &signed_validation,
    )
    .expect("verified signed introspection response");
    assert_eq!(
        signed_introspection.claims["token_introspection"]["active"],
        true
    );
    assert_eq!(
        signed_introspection.claims["token_introspection"]["client_id"],
        service_client_id
    );
    assert!(signed_introspection.claims.get("sub").is_none());
    let service_userinfo = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/default/userinfo")
            .insert_header((
                actix_web::http::header::AUTHORIZATION,
                format!("Bearer {service_token}"),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        service_userinfo.status(),
        actix_web::http::StatusCode::UNAUTHORIZED
    );
    let service_revocation = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/revoke")
            .insert_header((
                actix_web::http::header::AUTHORIZATION,
                service_basic.clone(),
            ))
            .set_form([("token", service_token)])
            .to_request(),
    )
    .await;
    assert_eq!(service_revocation.status(), actix_web::http::StatusCode::OK);
    let revoked_introspection = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/introspect")
            .insert_header((actix_web::http::header::AUTHORIZATION, service_basic))
            .set_form([("token", service_token)])
            .to_request(),
    )
    .await;
    let revoked_introspection_body: serde_json::Value =
        actix_web::test::read_body_json(revoked_introspection).await;
    assert_eq!(revoked_introspection_body, json!({"active": false}));
    let response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/")
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                "x".repeat(43),
            ))
            .to_request(),
    )
    .await;
    let removal = response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "robine_session")
        .expect("expired session cookie is removed");
    assert!(removal.value().is_empty());
    assert!(removal.max_age().is_some_and(|age| age.is_zero()));
    let opbs_removal = response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "robine_opbs")
        .expect("expired OP browser-state cookie is removed");
    assert!(opbs_removal.value().is_empty());
    assert!(opbs_removal.max_age().is_some_and(|age| age.is_zero()));

    let authorization_parameters = [
        ("response_type", "code"),
        ("client_id", "rust-development-client"),
        ("redirect_uri", "http://localhost:4002/callback"),
        ("scope", "openid profile email"),
        ("state", "sso-state"),
        ("nonce", "sso-nonce"),
        (
            "code_challenge",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("code_challenge_method", "S256"),
    ];
    let authorization_query =
        serde_urlencoded::to_string(authorization_parameters).expect("authorization query");
    let par_authorization_parameters = vec![
        ("response_type".to_owned(), "code".to_owned()),
        ("client_id".to_owned(), par_client_id.clone()),
        (
            "redirect_uri".to_owned(),
            "http://localhost:4002/callback".to_owned(),
        ),
        ("scope".to_owned(), "openid profile email".to_owned()),
        ("state".to_owned(), "sso-state".to_owned()),
        ("nonce".to_owned(), "sso-nonce".to_owned()),
        (
            "code_challenge".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        ),
        ("code_challenge_method".to_owned(), "S256".to_owned()),
    ];
    let par_peer = std::net::SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(
            (0xfd00_u128 << 112) | (Utc::now().timestamp_micros() as u128),
        )),
        12_345,
    );
    let pushed_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/par")
            .peer_addr(par_peer)
            .set_form(&par_authorization_parameters)
            .to_request(),
    )
    .await;
    assert_eq!(
        pushed_response.status(),
        actix_web::http::StatusCode::CREATED
    );
    assert_eq!(
        pushed_response
            .headers()
            .get(actix_web::http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let pushed_body: serde_json::Value = actix_web::test::read_body_json(pushed_response).await;
    let pushed_request_uri = pushed_body["request_uri"]
        .as_str()
        .expect("PAR request_uri");
    assert_eq!(pushed_body["expires_in"], 90);
    let rate_limited_pushed_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/par")
            .peer_addr(par_peer)
            .set_form(&par_authorization_parameters)
            .to_request(),
    )
    .await;
    assert_eq!(
        rate_limited_pushed_response.status(),
        actix_web::http::StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        rate_limited_pushed_response
            .headers()
            .get(actix_web::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("60")
    );
    let rate_limited_body: serde_json::Value =
        actix_web::test::read_body_json(rate_limited_pushed_response).await;
    assert_eq!(rate_limited_body["error"], "temporarily_unavailable");
    let pushed_query = serde_urlencoded::to_string([
        ("client_id", par_client_id.as_str()),
        ("request_uri", pushed_request_uri),
    ])
    .expect("pushed authorization reference query");
    let pushed_authorization_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/authorize?{pushed_query}"))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        pushed_authorization_response.status(),
        actix_web::http::StatusCode::FOUND
    );
    assert!(
        pushed_authorization_response
            .headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|location| location.contains("state=sso-state"))
    );
    let replayed_pushed_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/authorize?{pushed_query}"))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        replayed_pushed_response.status(),
        actix_web::http::StatusCode::BAD_REQUEST
    );

    let sso_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/authorize?{authorization_query}"))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(sso_response.status(), actix_web::http::StatusCode::FOUND);
    let sso_location = sso_response
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("SSO redirect");
    assert!(sso_location.contains("code="));
    assert!(sso_location.contains("state=sso-state"));
    let sso_redirect = url::Url::parse(sso_location).expect("SSO redirect URL");
    assert_eq!(
        sso_redirect
            .query_pairs()
            .find(|(key, _)| key == "iss")
            .map(|(_, value)| value.into_owned())
            .as_deref(),
        Some(web_issuer.as_str())
    );
    let session_state = sso_redirect
        .query_pairs()
        .find(|(key, _)| key == "session_state")
        .map(|(_, value)| value.into_owned())
        .expect("OIDC session state");
    assert_eq!(session_state.len(), 87);
    assert!(!session_state.contains(' '));
    let opbs = sso_response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "robine_opbs")
        .expect("OP browser state cookie");
    assert_eq!(opbs.value().len(), 43);
    assert!(!opbs.http_only().unwrap_or(false));

    let form_post_query = format!("{authorization_query}&response_mode=form_post&ui_locales=fr-FR");
    let form_post_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/authorize?{form_post_query}"))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(form_post_response.status(), actix_web::http::StatusCode::OK);
    assert_eq!(
        form_post_response
            .headers()
            .get(actix_web::http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        form_post_response
            .headers()
            .get(actix_web::http::header::CONTENT_LANGUAGE)
            .and_then(|value| value.to_str().ok()),
        Some("fr")
    );
    assert!(
        form_post_response
            .headers()
            .get(actix_web::http::header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("form-action http://localhost:4002;"))
    );
    let form_post_body = actix_web::test::read_body(form_post_response).await;
    let form_post_body = std::str::from_utf8(&form_post_body).expect("form_post HTML");
    assert!(form_post_body.contains("id=\"authorization-response-form\""));
    assert!(form_post_body.contains("action=\"http://localhost:4002/callback\""));
    assert!(form_post_body.contains("name=\"code\""));
    assert!(form_post_body.contains("name=\"state\" value=\"sso-state\""));
    assert!(form_post_body.contains(&format!("name=\"iss\" value=\"{web_issuer}\"")));
    assert!(form_post_body.contains("name=\"session_state\""));
    assert!(form_post_body.contains("<html lang=\"fr\">"));
    assert!(form_post_body.contains("Continuer vers votre application"));

    let jarm_query = format!("{authorization_query}&response_mode=query.jwt");
    let jarm_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/authorize?{jarm_query}"))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(jarm_response.status(), actix_web::http::StatusCode::FOUND);
    let jarm_location = jarm_response
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("JARM redirect");
    let jarm_url = url::Url::parse(jarm_location).expect("JARM redirect URL");
    assert!(jarm_url.query_pairs().all(|(name, _)| name == "response"));
    let jarm = jarm_url
        .query_pairs()
        .find(|(name, _)| name == "response")
        .map(|(_, value)| value.into_owned())
        .expect("JARM response parameter");
    let header = decode_header(&jarm).expect("JARM header");
    assert_eq!(header.typ.as_deref(), Some("oauth-authz-resp+jwt"));
    let key = database
        .public_signing_keys(&web_issuer)
        .await
        .expect("public signing keys")
        .into_iter()
        .find(|key| Some(key.kid.as_str()) == header.kid.as_deref())
        .expect("JARM signing key in JWKS");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[web_issuer.as_str()]);
    validation.set_audience(&["rust-development-client"]);
    let claims = decode::<serde_json::Value>(
        &jarm,
        &DecodingKey::from_rsa_components(&key.modulus, &key.exponent).expect("JARM decoding key"),
        &validation,
    )
    .expect("valid JARM signature")
    .claims;
    assert_eq!(claims["state"], "sso-state");
    assert!(
        claims["session_state"]
            .as_str()
            .is_some_and(|state| state.len() == 87 && !state.contains(' '))
    );
    assert!(claims["code"].as_str().is_some_and(|code| !code.is_empty()));
    assert_eq!(
        claims["exp"].as_i64(),
        claims["iat"].as_i64().map(|iat| iat + 60)
    );

    let hint_signing_key = database
        .signing_key(&web_issuer)
        .await
        .expect("ID token hint signing key");
    let now = Utc::now().timestamp();
    let id_token_hint = tokens::issue_id_token(
        &hint_signing_key,
        &IdTokenInput {
            issuer: &web_issuer,
            subject: "development-user",
            audience: "rust-development-client",
            session_id: None,
            nonce: Some("prior-nonce"),
            auth_time: Some(now),
            mfa_verified: false,
            at_hash: None,
            claims: &serde_json::Map::new(),
            now,
            lifetime: 300,
        },
    )
    .expect("ID token hint");
    let authorization_query_with_hint = |hint: &str, prompt: Option<&str>| {
        let mut parameters = authorization_parameters
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>();
        if let Some(prompt) = prompt {
            parameters.push(("prompt".to_owned(), prompt.to_owned()));
        }
        parameters.push(("id_token_hint".to_owned(), hint.to_owned()));
        serde_urlencoded::to_string(parameters).expect("authorization query with ID token hint")
    };
    let hinted_silent_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!(
                "/default/authorize?{}",
                authorization_query_with_hint(&id_token_hint, Some("none"))
            ))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        hinted_silent_response.status(),
        actix_web::http::StatusCode::FOUND
    );
    assert!(
        hinted_silent_response
            .headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|location| location.contains("code="))
    );

    let wrong_audience_hint = successful_device_body["id_token"]
        .as_str()
        .expect("device ID token");
    let wrong_audience_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!(
                "/default/authorize?{}",
                authorization_query_with_hint(wrong_audience_hint, Some("none"))
            ))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        wrong_audience_response.status(),
        actix_web::http::StatusCode::FOUND
    );
    assert!(
        wrong_audience_response
            .headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|location| location.contains("error=invalid_request"))
    );

    let other_subject_hint = tokens::issue_id_token(
        &hint_signing_key,
        &IdTokenInput {
            issuer: &web_issuer,
            subject: "other-user",
            audience: "rust-development-client",
            session_id: None,
            nonce: None,
            auth_time: Some(now),
            mfa_verified: false,
            at_hash: None,
            claims: &serde_json::Map::new(),
            now,
            lifetime: 300,
        },
    )
    .expect("other-subject ID token hint");
    let other_subject_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!(
                "/default/authorize?{}",
                authorization_query_with_hint(&other_subject_hint, Some("none"))
            ))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        other_subject_response.status(),
        actix_web::http::StatusCode::FOUND
    );
    assert!(
        other_subject_response
            .headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|location| location.contains("error=login_required"))
    );

    let interactive_other_subject = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!(
                "/default/authorize?{}",
                authorization_query_with_hint(&other_subject_hint, None)
            ))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        interactive_other_subject.status(),
        actix_web::http::StatusCode::OK
    );
    let interactive_csrf = interactive_other_subject
        .response()
        .cookies()
        .find(|cookie| cookie.name() == "robine_csrf")
        .expect("interactive ID token hint CSRF cookie")
        .value()
        .to_owned();
    let interactive_body = actix_web::test::read_body(interactive_other_subject).await;
    let interactive_body =
        std::str::from_utf8(&interactive_body).expect("interactive ID token hint page UTF-8");
    let interactive_transaction = hidden_form_value(interactive_body, "transaction");
    let interactive_login_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/authorize")
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_csrf",
                interactive_csrf.clone(),
            ))
            .set_form([
                ("transaction", interactive_transaction.as_str()),
                ("csrf_token", interactive_csrf.as_str()),
                ("identifier", "admin@example.com"),
                ("password", "change-me"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        interactive_login_response.status(),
        actix_web::http::StatusCode::FOUND
    );
    assert!(
        interactive_login_response
            .headers()
            .get(actix_web::http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|location| location.contains("error=login_required"))
    );

    let client_logout_initiation = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::post()
            .uri("/default/logout")
            .set_form([
                ("client_id", "rust-development-client"),
                (
                    "post_logout_redirect_uri",
                    "http://localhost:4002/signed-out",
                ),
                ("state", "client-logout-state"),
                ("ui_locales", "fr"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(
        client_logout_initiation.status(),
        actix_web::http::StatusCode::OK
    );
    let client_logout_body = actix_web::test::read_body(client_logout_initiation).await;
    assert!(
        client_logout_body
            .windows("id=\"logout-form\"".len())
            .any(|value| value == b"id=\"logout-form\"")
    );

    let expired_logout_hint = tokens::issue_id_token(
        &hint_signing_key,
        &IdTokenInput {
            issuer: &web_issuer,
            subject: "development-user",
            audience: "rust-development-client",
            session_id: None,
            nonce: None,
            auth_time: Some(now - 3_600),
            mfa_verified: false,
            at_hash: None,
            claims: &serde_json::Map::new(),
            now: now - 3_600,
            lifetime: 300,
        },
    )
    .expect("expired logout ID token hint");
    let expired_logout_query = serde_urlencoded::to_string([
        ("client_id", "rust-development-client"),
        ("id_token_hint", expired_logout_hint.as_str()),
        (
            "post_logout_redirect_uri",
            "http://localhost:4002/signed-out",
        ),
    ])
    .expect("expired logout hint query");
    let expired_logout_initiation = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/logout?{expired_logout_query}"))
            .to_request(),
    )
    .await;
    assert_eq!(
        expired_logout_initiation.status(),
        actix_web::http::StatusCode::OK
    );

    let silent_query = format!("{authorization_query}&prompt=none");
    let silent_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/authorize?{silent_query}"))
            .to_request(),
    )
    .await;
    assert_eq!(silent_response.status(), actix_web::http::StatusCode::FOUND);
    let silent_location = silent_response
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("silent error redirect");
    assert!(silent_location.contains("error=login_required"));
    assert!(silent_location.contains("state=sso-state"));
    assert_eq!(
        url::Url::parse(silent_location)
            .expect("silent error redirect URL")
            .query_pairs()
            .find(|(key, _)| key == "iss")
            .map(|(_, value)| value.into_owned())
            .as_deref(),
        Some(web_issuer.as_str())
    );

    let stale_silent_query = format!("{authorization_query}&prompt=none&max_age=0");
    let stale_silent_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/authorize?{stale_silent_query}"))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session.clone(),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        stale_silent_response.status(),
        actix_web::http::StatusCode::FOUND
    );
    let stale_silent_location = stale_silent_response
        .headers()
        .get(actix_web::http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("stale silent error redirect");
    assert!(stale_silent_location.contains("error=login_required"));

    let forced_login_query = format!("{authorization_query}&prompt=login");
    let forced_login_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri(&format!("/default/authorize?{forced_login_query}"))
            .cookie(actix_web::cookie::Cookie::new(
                "robine_session",
                sso_session,
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        forced_login_response.status(),
        actix_web::http::StatusCode::OK
    );
    let forced_login_body = actix_web::test::read_body(forced_login_response).await;
    assert!(
        forced_login_body
            .windows(15)
            .any(|value| value == b"id=\"login-form\"")
    );

    let ready_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/health/ready")
            .to_request(),
    )
    .await;
    assert_eq!(ready_response.status(), actix_web::http::StatusCode::OK);
    assert!(application.begin_draining());
    let draining_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/health/ready")
            .to_request(),
    )
    .await;
    assert_eq!(
        draining_response.status(),
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        actix_web::test::read_body_json::<serde_json::Value, _>(draining_response).await,
        serde_json::json!({"status": "not_ready"})
    );
    let metrics_response = actix_web::test::call_service(
        &app,
        actix_web::test::TestRequest::get()
            .uri("/metrics")
            .to_request(),
    )
    .await;
    let metrics_body = actix_web::test::read_body(metrics_response).await;
    let metrics_body = std::str::from_utf8(&metrics_body).expect("metrics are UTF-8");
    assert!(metrics_body.contains("robine_id_ready 0"));
    for grant_type in ["client_credentials", "device_code"] {
        let prefix = format!(
            "robine_id_token_issuance_total{{grant_type=\"{grant_type}\",outcome=\"success\"}} "
        );
        let count = metrics_body
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        assert!(count > 0, "missing successful {grant_type} issuance metric");
    }
    let userinfo_success = metrics_body
        .lines()
        .find_map(|line| line.strip_prefix("robine_id_userinfo_total{outcome=\"success\"} "))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    assert!(userinfo_success > 0, "missing successful UserInfo metric");
}

fn hidden_form_value(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    html.split_once(&marker)
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(value, _)| value.to_owned())
        .unwrap_or_else(|| panic!("hidden form value {name} is missing"))
}
