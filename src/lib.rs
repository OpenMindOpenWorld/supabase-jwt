//! # supabase-jwt
//!
//! A lightweight, framework-agnostic Rust library for validating Supabase Auth JWTs, with JWKS caching support.
//!
//! ## Features
//! - **Framework Agnostic**: Not dependent on any web framework, can be used in any Rust project.
//! - **JWKS-based**: Supports dynamic key fetching and caching from Supabase.
//! - **Stateless Validation**: Each request is validated independently for security.
//! - **High Performance**: Optimized parsing and validation with smart caching.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use supabase_jwt::{Claims, JwksCache};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Initialize the JWKS cache with your Supabase URL
//!     let jwks_url = "https://<your-project-ref>.supabase.co/auth/v1/jwks";
//!     let jwks_cache = JwksCache::new(jwks_url);
//!
//!     // 2. Get the Bearer Token from the request's Authorization header
//!     let bearer_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
//!
//!     // 3. Validate the JWT and extract claims
//!     match Claims::from_bearer_token(bearer_token, &jwks_cache).await {
//!         Ok(claims) => {
//!             // 4. Access user information securely
//!             println!("Successfully validated token for user: {}", claims.user_id());
//!         }
//!         Err(e) => {
//!             eprintln!("Authentication failed: {}", e);
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
// Module declarations for the library's internal components.
/// Handles JWT claims and validation logic.
mod claims;
/// Defines error types for the library.
mod error;
/// Manages JWKS fetching and caching.
mod jwks;
/// Provides JWT parsing functionalities.
mod parser;

// Test module, conditionally compiled only when running tests.
#[cfg(test)]
mod tests;

// Re-exporting key types and functions for a clean public API.
pub use claims::Claims;
pub use error::AuthError;
pub use jwks::JwksCache;
