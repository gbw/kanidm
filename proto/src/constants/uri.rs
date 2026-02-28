//! Shared URIs
//!
//! ⚠️  ⚠️   WARNING  ⚠️  ⚠️
//!
//! IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS EVERYWHERE
//!
//! SERIOUSLY... DO NOT CHANGE THEM!
//!
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS ⚠️  ⚠️
pub const OAUTH2_AUTHORISE: &str = "/oauth2/authorise";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS ⚠️  ⚠️
pub const OAUTH2_AUTHORISE_PERMIT: &str = "/oauth2/authorise/permit";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_AUTHORISE_REJECT: &str = "/oauth2/authorise/reject";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_AUTHORISE_DEVICE: &str = "/oauth2/device";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_TOKEN_ENDPOINT: &str = "/oauth2/token";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_TOKEN_INTROSPECT_ENDPOINT: &str = "/oauth2/token/introspect";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_TOKEN_REVOKE_ENDPOINT: &str = "/oauth2/token/revoke";

/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
/// This is the UI endpoint where users enter their device code (verification_uri)
/// It MUST start with /ui to avoid conflict with the API endpoint OAUTH2_AUTHORISE_DEVICE
pub const OAUTH2_DEVICE_LOGIN: &str = "/ui/oauth2/device";

pub const V1_AUTH_VALID: &str = "/v1/auth/valid";
