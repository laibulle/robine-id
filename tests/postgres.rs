use chrono::{Duration, Utc};
use robine_id::{database::Database, protocol::AuthorizationGrant};
use serde_json::json;

#[tokio::test]
#[ignore = "requires the development PostgreSQL service"]
async fn persists_and_atomically_consumes_security_state() {
    let database = Database::from_env().expect("DATABASE_URL and encryption secret");
    database.migrate().await.expect("migrations");
    let unique = format!("{}-{}", std::process::id(), Utc::now().timestamp_micros());
    let issuer = format!("https://id.example/{unique}");
    let subject = format!("subject-{unique}");
    let grant = AuthorizationGrant {
        issuer: issuer.clone(),
        subject: subject.clone(),
        client_id: "integration-client".to_owned(),
        redirect_uri: "https://app.example/callback".to_owned(),
        scopes: vec!["openid".to_owned()],
        nonce: Some("nonce".to_owned()),
        code_challenge: Some("a".repeat(43)),
        claims: json!({"name": "Integration"}),
        expires_at: Utc::now() + Duration::minutes(5),
    };

    let code = database
        .issue_authorization_code(&grant)
        .await
        .expect("authorization code");
    assert!(database
        .consume_authorization_code(&code)
        .await
        .expect("consume code")
        .is_some());
    assert!(database
        .consume_authorization_code(&code)
        .await
        .expect("replay code")
        .is_none());

    let pending = database
        .issue_pending_authorization(&grant, "state")
        .await
        .expect("pending authorization");
    assert!(database
        .consume_pending_authorization(&pending)
        .await
        .expect("consume pending")
        .is_some());
    assert!(database
        .consume_pending_authorization(&pending)
        .await
        .expect("replay pending")
        .is_none());

    let first = database
        .start_session(&subject, 2, 300)
        .await
        .expect("first session");
    let second = database
        .start_session(&subject, 2, 300)
        .await
        .expect("second session");
    let third = database
        .start_session(&subject, 2, 300)
        .await
        .expect("third session");
    assert!(database
        .validate_session(&first, 300)
        .await
        .expect("validate oldest")
        .is_none());
    assert!(database
        .validate_session(&second, 300)
        .await
        .expect("validate second")
        .is_some());
    assert!(database
        .validate_session(&third, 300)
        .await
        .expect("validate newest")
        .is_some());

    assert!(database
        .allow_authentication_attempt(&unique, 2, 60)
        .await
        .expect("rate attempt one"));
    assert!(database
        .allow_authentication_attempt(&unique, 2, 60)
        .await
        .expect("rate attempt two"));
    assert!(!database
        .allow_authentication_attempt(&unique, 2, 60)
        .await
        .expect("rate attempt three"));

    let initial = database.signing_key(&issuer).await.expect("initial key");
    let (rotated, changed) = database
        .rotate_signing_key(&issuer, "integration-rotation")
        .await
        .expect("key rotation");
    let (unchanged, changed_again) = database
        .rotate_signing_key(&issuer, "integration-rotation")
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
}
