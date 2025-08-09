//! Defines the error types that can occur during JWT authentication.
//!
//! This module provides a comprehensive set of errors that may arise
//! during the parsing and validation of JWTs, and is independent of any
//! specific web framework.

use thiserror::Error;

/// Represents errors that can occur during JWT authentication.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum AuthError {
    /// The authentication token is missing or invalid.
    #[error("missing or invalid authentication token")]
    InvalidToken,

    /// Failed to decode the token's header.
    #[error("failed to decode token header")]
    DecodeHeader,

    /// No matching key was found in the JSON Web Key Set (JWKS).
    #[error("failed to find matching key in JWKS")]
    NoMatchingKey,

    /// The key type is not supported by Supabase.
    #[error("unsupported key type for Supabase: {0}")]
    UnsupportedKeyType(String),

    /// The cryptographic curve is not supported by Supabase.
    #[error("unsupported curve for Supabase: {0}")]
    UnsupportedCurve(String),

    /// A component of the cryptographic key is invalid.
    #[error("invalid key component: {0}")]
    InvalidKeyComponent(String),

    /// Failed to decode from Base64.
    #[error("base64 decode error: {0}")]
    Base64Decode(String),

    /// The signing algorithm is invalid or not supported.
    #[error("invalid algorithm")]
    InvalidAlgorithm,

    /// The token's signature verification failed.
    #[error("token verification failed")]
    Verification,

    /// The claims within the token are invalid (e.g., `exp` or `iss`).
    #[error("invalid claims")]
    InvalidClaims,

    /// An internal error occurred within the JWKS handling.
    #[error("internal JWKS error: {0}")]
    JwksError(String),

    /// The token format is malformed.
    #[error("malformed token format")]
    MalformedToken,

    /// A network error occurred during a request.
    #[error("network error: {0}")]
    NetworkError(String),
}
