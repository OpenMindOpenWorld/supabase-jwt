//! # JWT Claims
//!
//! This module provides the `Claims` struct, which represents the deserialized data
//! from a Supabase Auth JWT. It is designed to be a simple data carrier with
//! convenient methods for accessing standard JWT claims and Supabase-specific metadata.
//!
//! The actual JWT parsing and validation logic is handled by the `JwtParser`,
//! and this module focuses on providing a strongly-typed structure for the claims
//! once they have been successfully validated.

use crate::{error::AuthError, jwks::JwksCache, parser::JwtParser};
use serde::{Deserialize, Serialize};

/// Represents the claims of a Supabase JWT.
///
/// This struct acts as a data carrier for all the claims contained within a JWT,
/// making it easy to access user information and metadata. The validation logic
/// is handled by the `JwtParser` before the claims are instantiated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// (Subject) The user ID.
    pub sub: String,
    /// (Expiration Time) The timestamp when the token expires.
    pub exp: usize,
    /// (Issued At) The timestamp when the token was issued.
    pub iat: Option<usize>,
    /// (JWT ID) A unique identifier for the token.
    pub jti: Option<String>,
    /// The user's email address.
    pub email: Option<String>,
    /// The user's phone number.
    pub phone: Option<String>,
    /// The user's role.
    pub role: Option<String>,
    /// Application-specific metadata.
    pub app_metadata: Option<serde_json::Value>,
    /// User-specific metadata.
    pub user_metadata: Option<serde_json::Value>,
    /// (Audience) The recipient for which the JWT is intended.
    pub aud: Option<String>,
    /// (Issuer) The principal that issued the JWT.
    pub iss: Option<String>,
    /// (Authentication Assurance Level) The level of assurance.
    pub aal: Option<String>,
    /// (Authentication Methods References) A list of authentication methods.
    pub amr: Option<Vec<serde_json::Value>>,
    /// The session ID.
    pub session_id: Option<String>,
    /// Indicates if the user is anonymous.
    pub is_anonymous: Option<bool>,
    /// (Key ID) The ID of the key used to sign the token. Not serialized.
    #[serde(skip)]
    pub kid: Option<String>,
}

impl Claims {
    /// Parses and validates claims from a raw JWT string.
    ///
    /// # Arguments
    ///
    /// * `token` - The raw JWT string.
    /// * `jwks_cache` - A reference to the `JwksCache` for key retrieval.
    ///
    /// # Returns
    ///
    /// A `Result` containing the validated `Claims` or an `AuthError`.
    pub async fn from_token(token: &str, jwks_cache: &JwksCache) -> Result<Self, AuthError> {
        let jwt_header = JwtParser::decode_header(token)?;
        let kid = jwt_header.kid.ok_or(AuthError::InvalidToken)?;

        let jwk = jwks_cache.find_key(&kid).await?;
        let decoding_key = JwtParser::create_decoding_key(&jwk)?;
        let algorithm = JwtParser::parse_algorithm(&jwt_header.alg)?;

        let mut claims = JwtParser::verify_and_decode(token, &decoding_key, algorithm)?;
        claims.kid = Some(kid);

        claims.validate_security()?;

        Ok(claims)
    }

    /// Parses and validates claims from a "Bearer" token string.
    ///
    /// This method expects the token to be prefixed with "Bearer ".
    ///
    /// # Arguments
    ///
    /// * `bearer_token` - The Bearer token string (e.g., "Bearer eyJ...").
    /// * `jwks_cache` - A reference to the `JwksCache` for key retrieval.
    ///
    /// # Returns
    ///
    /// A `Result` containing the validated `Claims` or an `AuthError`.
    pub async fn from_bearer_token(
        bearer_token: &str,
        jwks_cache: &JwksCache,
    ) -> Result<Self, AuthError> {
        let token = bearer_token
            .strip_prefix("Bearer ")
            .ok_or(AuthError::MalformedToken)?;

        Self::from_token(token, jwks_cache).await
    }

    /// Performs basic security validation on the claims.
    ///
    /// This validation is minimal, trusting that Supabase Auth has already performed
    /// comprehensive checks. It primarily ensures that the subject (user ID) is not empty.
    pub fn validate_security(&self) -> Result<(), AuthError> {
        if self.sub.trim().is_empty() {
            return Err(AuthError::InvalidClaims);
        }
        Ok(())
    }
}

// Data access methods
impl Claims {
    /// Returns the user ID (subject).
    pub fn user_id(&self) -> &str {
        &self.sub
    }

    /// Returns the user's email, if available.
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Returns the user's role, defaulting to "authenticated".
    pub fn role(&self) -> &str {
        self.role.as_deref().unwrap_or("authenticated")
    }

    /// Returns the user's phone number, if available.
    pub fn phone(&self) -> Option<&str> {
        self.phone.as_deref()
    }

    /// Checks if the user is anonymous.
    pub fn is_anonymous(&self) -> bool {
        self.is_anonymous.unwrap_or(false)
    }
}

// Metadata access methods
impl Claims {
    /// Retrieves a specific field from the user metadata.
    ///
    /// # Arguments
    ///
    /// * `key` - The key of the metadata field to retrieve.
    ///
    /// # Returns
    ///
    /// An `Option` containing the deserialized value if the key exists.
    pub fn get_user_metadata<T>(&self, key: &str) -> Option<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.user_metadata
            .as_ref()
            .and_then(|metadata| metadata.get(key))
            .and_then(|value| serde_json::from_value(value.clone()).ok())
    }

    /// Retrieves a specific field from the application metadata.
    ///
    /// # Arguments
    ///
    /// * `key` - The key of the metadata field to retrieve.
    ///
    /// # Returns
    ///
    /// An `Option` containing the deserialized value if the key exists.
    pub fn get_app_metadata<T>(&self, key: &str) -> Option<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.app_metadata
            .as_ref()
            .and_then(|metadata| metadata.get(key))
            .and_then(|value| serde_json::from_value(value.clone()).ok())
    }
}
