//! Authentication tests: token validation, tenant extraction, and the HTTP
//! extractor. Keys are a throwaway pair generated only for this file.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::FromRequestParts;
use axum::http::Request;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::{json, Value};

use rust_control_plane::auth::{AuthError, JwksCache, JwtVerifier, Principal};
use rust_control_plane::config::{AppConfig, IdentityConfig};
use rust_control_plane::state::AppState;

const KID: &str = "test-key-1";
const ISSUER: &str = "https://issuer.test/realms/agentic";
const AUDIENCE: &str = "rust-control-plane";
const TENANT: &str = "tenant-acme";

// Test-only key. Never valid for any deployed environment.
const PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCs5rBy05i7KLj6
T1YT+OfJY0svRhKwqtuxLmX929DcD4U/2am7hH9mCBcFymydGs96PlaQCt6XuFYs
8Rxqy0fxRA8FpBSeUTMDMw7ZjnfzJ71X2ezCIJISk0qmEKEGmitlO/83cwbP6Xhr
ruhug8yfo1XbsKBHUCmZY/dm4WtY2QiUWFIn3ZfmhCAxt5XbeMa/UyKfJQ6Ghn4m
Joj8tdmeQpGHlJO6nIxxl7vZiR2v6gR2U86LrCc377rIio1EWBlnTz7ab+YyX2M1
xi9s9KzkYEfeHUcSBGsi0ahKyJ8rUmLNtnm5pma5v6u/lrMbgdpuWdNp3cjxATYk
1gTgynuPAgMBAAECggEAM8gdJS6Y6ciO6axUB8Q+StKZhE10sINjK2PNeONZ4GYn
jpFWI4pRi1G1726J691JMP+1dgtDUeYLrQcC7zr1T10GMLbM1ANWh0lF08M2ylRn
AQYLwbH2fWiubSDC0RLgF0AKNeWVrzPpdDqccui3IkJNJu/1eJYZ9034nM+7Eg7i
1SSx9yeYt5HHzZcNxzQ5QzTTFACHSthMP1gJ+sFZyZlygvySmLez4p6ENmt8CqIM
OPKE1NJroyfqvUoWESXrVjks7kjgtzum6BcOmx/AaGmCV04D/2QL0o04QDLMFpT4
WoJpXB2dAOBa8Empvww8y0JjbTf51Q7LqQ5pP7MeTQKBgQDvHFOkwDVDPWX/pU01
/k31WYjTuo6nP6NIjL7UMiWe5uS1dElzZWXmI406M/CDv8w0fzkb7M72xHg55658
gXHbbVAojx9Ekt3+D4qaUtd5FCgzpHPFNzb5pW/PM533Gp/uAedBtYNOhmZjmTIC
nfEhgP7leowYZHK2OvghwqbgtQKBgQC5HSQuXmjH3dmqn2G95L7DqGY7jXJDoC9L
SAAfIgZieMVE4Em6yIxTxy9chWCkItApx2WKef0HDu5lx2vzS1dyx2pyqiplYFjI
vfEmgjl8TcV2BFneplmN3QaC0Aem7pvQhvwo8CzctJYfevMDa9IVIK09q95vZ91/
cH0FGYEJswKBgQDN9PZPGIhITKCI3VduRIfd56slxLGPeg8pNKJCoJcrEfK6IVoL
HbHx03mYQpjOwuwf493LIeT7RSvRpK/06oKp4LSE2xKxvFeeuMBIQUb8MdKW+PYH
T5H44vk13l4YNETBe744KSLbBoU3EQO0oVrL4xKrky0M7aipMo38dm/LaQKBgC3u
4zl2R73AePBzmAdMqWFXefaxBHdvWgzuEsmm4bqxiRGsLd9hQCDRvhjRJ8fSs6CK
T9HqrzR/KfyrXUgDm/FpNiq5usdo/t7g8uPBUI5dpe/A6KPs1y/ydlkjUaLEdnlp
5UwrPJaPYOjy0zY4HOsNLq+s5Ab02Ot0eDE5wOEtAoGBAMXlaCUFC9SFFkq26dxM
uKFp0Y11G9b8LPf+CJuB9nnnfV9vPUVHzvbg58uehLAi160ZOLjQu1oujBI/iNg9
a+kPM7N7faIFDHfjOsL2rLeXYrELLwZIO6vou7Jq/DbPSpWWPKUf36VTFbzv3KqN
MxSxtVL2Mg24RK8dMtz/bEuk
-----END PRIVATE KEY-----
"#;

const PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArOawctOYuyi4+k9WE/jn
yWNLL0YSsKrbsS5l/dvQ3A+FP9mpu4R/ZggXBcpsnRrPej5WkArel7hWLPEcastH
8UQPBaQUnlEzAzMO2Y538ye9V9nswiCSEpNKphChBporZTv/N3MGz+l4a67oboPM
n6NV27CgR1ApmWP3ZuFrWNkIlFhSJ92X5oQgMbeV23jGv1MinyUOhoZ+JiaI/LXZ
nkKRh5STupyMcZe72Ykdr+oEdlPOi6wnN++6yIqNRFgZZ08+2m/mMl9jNcYvbPSs
5GBH3h1HEgRrItGoSsifK1JizbZ5uaZmub+rv5azG4HablnTad3I8QE2JNYE4Mp7
jwIDAQAB
-----END PUBLIC KEY-----
"#;

fn identity() -> IdentityConfig {
    IdentityConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        jwks_uri: "https://issuer.test/jwks".into(),
        tenant_claim: "tenant_id".into(),
        leeway: Duration::from_secs(30),
        jwks_ttl: Duration::from_secs(300),
        jwks_timeout: Duration::from_secs(5),
    }
}

fn verifier() -> JwtVerifier {
    let mut keys = HashMap::new();
    let key = DecodingKey::from_rsa_pem(PUBLIC_KEY.as_bytes()).expect("test public key");
    keys.insert(KID.to_string(), key);

    JwtVerifier::new(
        identity(),
        JwksCache::from_keys("https://issuer.test/jwks", keys),
    )
}

fn state() -> AppState {
    AppState::with_verifier(
        AppConfig {
            bind_addr: "127.0.0.1:0".parse().expect("socket address"),
            identity: identity(),
        },
        verifier(),
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn claims() -> Value {
    json!({
        "sub": "user-1",
        "iss": ISSUER,
        "aud": [AUDIENCE, "account"],
        "exp": now() + 300,
        "iat": now(),
        "jti": "token-1",
        "scope": "openid profile",
        "tenant_id": TENANT,
    })
}

fn sign(claims: &Value) -> String {
    sign_with_kid(claims, KID)
}

fn sign_with_kid(claims: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).expect("test private key");
    encode(&header, claims, &key).expect("sign token")
}

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
