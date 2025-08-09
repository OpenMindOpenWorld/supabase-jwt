//! # JWT Parsing and Validation Module
//!
//! High-performance JWT parser designed for Supabase Auth.
//!
//! ## Features
//! - **Stateless Parsing**: Independent validation for each request
//! - **Security Validation**: Complete signature, time, and format verification
//! - **High Performance**: Optimized Base64 decoding and JSON parsing
//!
//! ## Requirements
//! - Only handles Supabase Auth generated JWT tokens
//! - Fixed ES256 (ECC P-256) algorithm
//! - Trusted JWKS source through smart caching

use super::claims::Claims;
use super::jwks::Jwk;
use crate::error::AuthError;
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// JWT Header structure.
///
/// Contains information from the JWT token header.
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtHeader {
    /// Algorithm
    pub alg: String,
    /// Key ID
    pub kid: Option<String>,
    /// Token type
    pub typ: Option<String>,
}

/// JWT Parser.
///
/// Provides JWT token parsing and validation functionality.
pub struct JwtParser;

impl JwtParser {
    /// Algorithm used by Supabase Auth.
    /// Fixed to ES256 (ECC P-256)
    const SUPABASE_ALGORITHM: &str = "ES256";

    /// Decodes JWT header to extract Key ID and algorithm information.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT token string
    pub fn decode_header(token: &str) -> Result<JwtHeader, AuthError> {
        // Basic format check: JWT token format should be header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 || parts[0].is_empty() {
            return Err(AuthError::InvalidToken);
        }

        // Log each part's length for debugging
        tracing::debug!(
            "JWT parts lengths - header: {}, payload: {}, signature: {}",
            parts[0].len(),
            parts[1].len(),
            parts[2].len()
        );

        // Check for invalid characters (JWT should only contain base64url chars: A-Z, a-z, 0-9, -, _)
        // Note: Standard base64url doesn't use padding '=', but some implementations may include it
        for (i, part) in parts.iter().enumerate() {
            if part
                .chars()
                .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '=')
            {
                tracing::warn!(
                    "JWT part {} contains invalid characters: {}",
                    i,
                    if part.len() > 20 { &part[..20] } else { part }
                );
                return Err(AuthError::InvalidToken);
            }
        }

        // Base64 decode header part
        let header_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| AuthError::DecodeHeader)?;

        // Parse JSON header
        let header: JwtHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| AuthError::DecodeHeader)?;

        // Verify algorithm matches Supabase standard
        if header.alg != Self::SUPABASE_ALGORITHM {
            return Err(AuthError::InvalidAlgorithm);
        }

        Ok(header)
    }

    /// Creates a decoding key from JWK.
    ///
    /// # Arguments
    ///
    /// * `jwk` - JSON Web Key
    pub fn create_decoding_key(jwk: &Jwk) -> Result<DecodingKey, AuthError> {
        match jwk.kty.as_str() {
            "EC" => {
                // Supabase uses ECC P-256 elliptic curve keys
                let x = jwk.x.as_ref().ok_or_else(|| {
                    AuthError::InvalidKeyComponent("Missing x coordinate for EC key".to_string())
                })?;
                let y = jwk.y.as_ref().ok_or_else(|| {
                    AuthError::InvalidKeyComponent("Missing y coordinate for EC key".to_string())
                })?;
                let crv = jwk.crv.as_ref().ok_or_else(|| {
                    AuthError::InvalidKeyComponent("Missing curve type for EC key".to_string())
                })?;

                // Verify P-256 curve (Supabase standard)
                if crv != "P-256" {
                    return Err(AuthError::UnsupportedCurve(format!(
                        "Expected P-256, but got {crv}"
                    )));
                }

                let x_bytes = general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .map_err(|e| AuthError::Base64Decode(format!("Failed to decode x: {e}")))?;
                let y_bytes = general_purpose::URL_SAFE_NO_PAD
                    .decode(y)
                    .map_err(|e| AuthError::Base64Decode(format!("Failed to decode y: {e}")))?;

                // P-256 coordinate length is fixed at 32 bytes
                const P256_COORD_LEN: usize = 32;
                if x_bytes.len() != P256_COORD_LEN || y_bytes.len() != P256_COORD_LEN {
                    return Err(AuthError::InvalidKeyComponent(format!(
                        "Invalid P-256 coordinate length: got x={}, y={} (expected: {P256_COORD_LEN})",
                        x_bytes.len(),
                        y_bytes.len()
                    )));
                }

                // Construct decoding key directly from EC components
                DecodingKey::from_ec_components(x, y).map_err(|e| {
                    AuthError::InvalidKeyComponent(format!(
                        "Failed to create key from EC components: {e}"
                    ))
                })
            }
            unsupported_kty => {
                // Supabase only uses EC keys
                Err(AuthError::UnsupportedKeyType(unsupported_kty.to_string()))
            }
        }
    }

    /// Verifies and decodes JWT token.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT token string
    /// * `decoding_key` - Decoding key
    /// * `algorithm` - Verification algorithm
    pub fn verify_and_decode(
        token: &str,
        decoding_key: &DecodingKey,
        algorithm: Algorithm,
    ) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;
        validation.validate_aud = false; // Supabase may not set aud
        validation.validate_nbf = true; // Validate "not before" time

        // Set time tolerance to 30 seconds to handle clock skew
        validation.leeway = 30;

        // Validate issuer if needed
        // validation.iss = Some("expected-issuer".to_string());

        let token_data = decode::<Claims>(token, decoding_key, &validation).map_err(|e| {
            tracing::warn!("JWT validation failed: {:?}", e);
            AuthError::Verification
        })?;

        // jsonwebtoken library already handles time validation
        tracing::debug!(
            "JWT validation successful for user: {}",
            token_data.claims.sub
        );

        Ok(token_data.claims)
    }

    /// Parses Supabase JWT algorithm.
    ///
    /// # Arguments
    ///
    /// * `alg` - Algorithm string (should be "ES256")
    pub fn parse_algorithm(alg: &str) -> Result<Algorithm, AuthError> {
        if alg == Self::SUPABASE_ALGORITHM {
            Ok(Algorithm::ES256)
        } else {
            tracing::warn!(
                "Unsupported JWT algorithm for Supabase: {} (expected: {})",
                alg,
                Self::SUPABASE_ALGORITHM
            );
            Err(AuthError::InvalidAlgorithm)
        }
    }
}

// Tests have been moved to the unified tests module.
// See: src/tests/parser_tests.rs
