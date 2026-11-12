//! Authentication tests: token validation, tenant extraction, and the HTTP
//! extractor. Keys and token fixtures live in `tests/common`.

mod common;

use axum::extract::FromRequestParts;
use axum::http::Request;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;

use common::{claims, now, sign, sign_with_kid, state, verifier, AUDIENCE, ISSUER, KID, TENANT};
use rust_control_plane::auth::{AuthError, Principal};

async fn principal_from(header_value: Option<&str>) -> Result<Principal, AuthError> {
    let mut builder = Request::builder().uri("/v1/me");
    if let Some(value) = header_value {
        builder = builder.header("authorization", value);
    }
    let (mut parts, _) = builder.body(()).expect("request").into_parts();

    Principal::from_request_parts(&mut parts, &state()).await
}

#[tokio::test]
async fn valid_token_yields_principal() {
    let principal = verifier().verify(&sign(&claims())).await.expect("valid");

    assert_eq!(principal.subject, "user-1");
    assert_eq!(principal.tenant_id, TENANT);
    assert_eq!(principal.issuer, ISSUER);
    assert_eq!(principal.audiences, vec![AUDIENCE, "account"]);
    assert_eq!(principal.scopes, vec!["openid", "profile"]);
    assert_eq!(principal.token_id.as_deref(), Some("token-1"));
    assert!(principal.has_scope("profile"));
    assert!(!principal.has_scope("admin"));
}

#[tokio::test]
async fn single_string_audience_is_accepted() {
    let mut claims = claims();
    claims["aud"] = json!(AUDIENCE);

    let principal = verifier().verify(&sign(&claims)).await.expect("valid");
    assert_eq!(principal.audiences, vec![AUDIENCE]);
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let mut claims = claims();
    claims["exp"] = json!(now() - 3_600);

    assert!(matches!(
        verifier().verify(&sign(&claims)).await,
        Err(AuthError::Expired)
    ));
}

#[tokio::test]
async fn token_from_wrong_issuer_is_rejected() {
    let mut claims = claims();
    claims["iss"] = json!("https://attacker.test/realms/agentic");

    assert!(matches!(
        verifier().verify(&sign(&claims)).await,
        Err(AuthError::InvalidIssuer)
    ));
}

#[tokio::test]
async fn token_for_wrong_audience_is_rejected() {
    let mut claims = claims();
    claims["aud"] = json!(["some-other-api"]);

    assert!(matches!(
        verifier().verify(&sign(&claims)).await,
        Err(AuthError::InvalidAudience)
    ));
}

#[tokio::test]
async fn missing_tenant_claim_is_rejected() {
    let mut claims = claims();
    claims.as_object_mut().expect("object").remove("tenant_id");

    assert!(matches!(
        verifier().verify(&sign(&claims)).await,
        Err(AuthError::MissingTenant(claim)) if claim == "tenant_id"
    ));
}

#[tokio::test]
async fn empty_tenant_claim_is_rejected() {
    let mut claims = claims();
    claims["tenant_id"] = json!("   ");

    assert!(matches!(
        verifier().verify(&sign(&claims)).await,
        Err(AuthError::MissingTenant(_))
    ));
}

#[tokio::test]
async fn unknown_key_id_is_rejected() {
    assert!(matches!(
        verifier()
            .verify(&sign_with_kid(&claims(), "rotated-away"))
            .await,
        Err(AuthError::UnknownKeyId)
    ));
}

#[tokio::test]
async fn non_rs256_tokens_are_rejected() {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID.to_string());
    let token = encode(
        &header,
        &claims(),
        &EncodingKey::from_secret(b"not-the-signing-key"),
    )
    .expect("sign");

    assert!(matches!(
        verifier().verify(&token).await,
        Err(AuthError::UnsupportedAlgorithm)
    ));
}

#[tokio::test]
async fn token_not_yet_valid_is_rejected() {
    let mut claims = claims();
    claims["nbf"] = json!(now() + 3_600);

    assert!(matches!(
        verifier().verify(&sign(&claims)).await,
        Err(AuthError::NotYetValid)
    ));
}

#[tokio::test]
async fn extractor_rejects_missing_authorization_header() {
    assert!(matches!(
        principal_from(None).await,
        Err(AuthError::MissingToken)
    ));
}

#[tokio::test]
async fn extractor_rejects_non_bearer_credentials() {
    assert!(matches!(
        principal_from(Some("Basic dXNlcjpwYXNz")).await,
        Err(AuthError::MalformedHeader)
    ));
}

#[tokio::test]
async fn extractor_accepts_bearer_token() {
    let token = sign(&claims());
    let principal = principal_from(Some(&format!("Bearer {token}")))
        .await
        .expect("authenticated");

    assert_eq!(principal.tenant_id, TENANT);
}

#[tokio::test]
async fn extractor_accepts_lowercase_bearer_scheme() {
    let token = sign(&claims());
    let principal = principal_from(Some(&format!("bearer {token}")))
        .await
        .expect("authenticated");

    assert_eq!(principal.subject, "user-1");
}
