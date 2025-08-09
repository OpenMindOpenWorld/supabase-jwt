# supabase-jwt

[![Crates.io](https://img.shields.io/crates/v/supabase-jwt.svg)](https://crates.io/crates/supabase-jwt)
[![Docs.rs](https://docs.rs/supabase-jwt/badge.svg)](https://docs.rs/supabase-jwt)
[![Build Status](https://img.shields.io/github/actions/workflow/status/supabase-community/supabase-jwt-rs/ci.yml?branch=main)](https://github.com/supabase-community/supabase-jwt-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/supabase-jwt.svg)](https://github.com/supabase-community/supabase-jwt-rs/blob/main/LICENSE-MIT)

English | [简体中文](README-zh_CN.md)

A lightweight, framework-agnostic Rust library for validating Supabase Auth JWTs, with JWKS caching support.

## Table of Contents

- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [🔧 Installation](#-installation)
- [🧩 Framework Integration Examples](#-framework-integration-examples)
  - [Axum](#axum)
  - [Actix Web](#actix-web)
- [📖 API Overview](#-api-overview)
- [🏛️ Design Philosophy](#️-design-philosophy)
- [✅ Testing and Quality](#-testing-and-quality)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

## ✨ Features

- 🚀 **High-performance**: Smart JWKS caching to reduce network requests.
- 🔒 **Secure**: Optimized for the Supabase Auth ES256 algorithm.
- 🎯 **Simple**: Framework-agnostic with a simple API design for easy integration.
- ⚡ **Asynchronous**: Purely asynchronous design based on `tokio`.
- 🛡️ **Reliable**: Thoroughly tested with >94% code coverage.

## 🚀 Quick Start

```rust
use supabase_jwt::{Claims, JwksCache};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize the JWKS cache
    // Get the URL from your Supabase project's API settings
    let jwks_url = "https://<your-project-ref>.supabase.co/auth/v1/jwks";
    let jwks_cache = JwksCache::new(jwks_url);

    // 2. Get the Bearer Token from the request
    let bearer_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."; // Get from Authorization header

    // 3. Validate the JWT and extract claims
    // from_bearer_token automatically handles the "Bearer " prefix
    match Claims::from_bearer_token(bearer_token, &jwks_cache).await {
        Ok(claims) => {
            // 4. Access user information
            println!("User ID: {}", claims.user_id());
            println!("Email: {:?}", claims.email());
            println!("Role: {}", claims.role());
            println!("Issued at: {}", claims.issued_at());
            println!("Expires at: {}", claims.expires_at());
        }
        Err(e) => {
            eprintln!("Token validation failed: {:?}", e);
        }
    }

    Ok(())
}
```

## 🔧 Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
supabase-jwt = "0.1.0" # Please check for the latest version on crates.io
tokio = { version = "1.47.0", features = ["full"] }
```

## 🧩 Framework Integration Examples

### Axum

It's recommended to use `axum-extra` to elegantly extract the Bearer Token.

```rust
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use axum_extra::headers::{authorization::Bearer, Authorization};
use axum_extra::TypedHeader;
use supabase_jwt::{Claims, JwksCache};
use std::sync::Arc;

async fn protected_handler(
    State(jwks_cache): State<Arc<JwksCache>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = Claims::from_token(bearer.token(), &jwks_cache)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(Json(serde_json::json!({
        "user_id": claims.user_id(),
        "email": claims.email()
    })))
}

/*
// Set the state in your application
async fn run_app() {
    let jwks_cache = Arc::new(JwksCache::new("..."));
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .with_state(jwks_cache);

    // Start the server...
}
*/
```

### Actix Web

In Actix Web, you can manually extract the token from the request headers.

```rust
use actix_web::{web, HttpRequest, HttpResponse, Result};
use supabase_jwt::{Claims, JwksCache};

async fn protected_handler(
    req: HttpRequest,
    jwks_cache: web::Data<JwksCache>,
) -> Result<HttpResponse> {
    let bearer_token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Missing authorization header"))?;

    let claims = Claims::from_bearer_token(bearer_token, &jwks_cache)
        .await
        .map_err(|e| {
            eprintln!("Token validation error: {:?}", e);
            actix_web::error::ErrorUnauthorized("Invalid token")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user_id": claims.user_id(),
        "role": claims.role()
    })))
}
```

## 📖 API Overview

The `Claims` struct provides convenient methods to access standard and custom information in the JWT.

```rust
// Basic information
let user_id = claims.user_id();        // User ID (sub)
let email = claims.email();            // Email (email)
let role = claims.role();              // Role (role)
let phone = claims.phone();            // Phone number (phone)
let is_anon = claims.is_anonymous();   // Whether the user is anonymous (is_anonymous)

// Timestamps
let issued_at = claims.issued_at();    // Issued at (iat)
let expires_at = claims.expires_at();  // Expires at (exp)

// Metadata
// Assuming user_metadata = {"custom_field": "value"}
let custom_field: Option<String> = claims.get_user_metadata("custom_field");

// Assuming app_metadata = {"feature_enabled": true}
let app_setting: Option<bool> = claims.get_app_metadata("feature_enabled");
```

`JwksCache` provides a smart key caching mechanism to efficiently validate tokens.

```rust
let jwks_cache = JwksCache::new("https://<project>.supabase.co/auth/v1/jwks");

// Automatically fetch JWKS from cache or network
let jwks = jwks_cache.get_jwks().await?;

// Find a specific key (usually called internally by from_token)
let key = jwks_cache.find_key("key_id").await?;
```

For more details, please refer to the [**full API documentation on docs.rs**](https://docs.rs/supabase-jwt).

## 🚀 Advanced Usage

### Error Handling

It's good practice to handle different authentication errors gracefully. `from_bearer_token` returns a detailed `AuthError` enum.

```rust
use supabase_jwt::{AuthError, Claims, JwksCache};

async fn handle_request(bearer_token: &str, jwks_cache: &JwksCache) {
    match Claims::from_bearer_token(bearer_token, jwks_cache).await {
        Ok(claims) => {
            println!("Successfully validated token for user: {}", claims.user_id());
        }
        Err(e) => {
            eprintln!("Authentication failed: {}", e);
            // Example of handling specific errors
            match e {
                AuthError::InvalidToken => {
                    // Trigger re-authentication
                }
                AuthError::Verification => {
                    // Token signature is invalid, might be a security risk
                }
                AuthError::JwksError(_) => {
                    // Could be a network issue or Supabase outage
                }
                _ => {
                    // Handle other cases
                }
            }
        }
    }
}
```

### Cache Behavior

`JwksCache` is designed for high availability and performance with a built-in smart caching strategy, requiring no manual configuration:

- **Normal Cache**: JWKS are cached for **24 hours**.
- **Fallback Cache**: If fetching new keys fails (e.g., due to a network error), the cache will continue to serve the last known valid keys for up to **7 days**. This prevents your application from failing if the Supabase Auth service is temporarily unavailable.
- **Network Timeout**: All network requests to the JWKS endpoint have a **5-second timeout** to prevent your application from hanging.


## 🏛️ Design Philosophy

This library is based on the design philosophy of "Trust Supabase Auth, focus on parsing stability":

- **Trust Upstream**: Trust the legality of the token format and content generated by Supabase Auth.
- **Focus on Parsing**: Focus on ensuring the stability and performance of the parsing process.
- **Fail Fast**: Immediately reject abnormal tokens to avoid excessive validation.
- **Cache Optimization**: Smart JWKS caching to reduce network overhead.

## ✅ Testing and Quality

We take code quality and reliability very seriously and ensure it through a comprehensive testing strategy.

- **Test Coverage**: Achieved **>94%** code coverage using `cargo-tarpaulin`.
- **Test Cases**: Over **100** test cases covering core logic, edge cases, and integration scenarios.
- **Mock Services**: Use `wiremock` to simulate the Supabase Auth API, ensuring test stability and independence.

You can run the tests with the following commands:
```bash
# Run all tests
cargo test

# Calculate code coverage
cargo tarpaulin --include-tests
```

## 🤝 Contributing

Issues and Pull Requests are welcome! Before contributing, please ensure:

1. Run `cargo fmt` to format the code.
2. Run `cargo clippy` to check code quality.
3. Run `cargo test` to ensure all tests pass.

## 📜 License

This project is dual-licensed under MIT or Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.