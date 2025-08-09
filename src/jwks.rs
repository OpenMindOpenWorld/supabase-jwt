//! # JWKS (JSON Web Key Set) Smart Cache Management Module
//!
//! A JWKS caching system for Supabase Auth with graceful fallback.
//!
//! ## Features
//! - **Smart Caching**: 24-hour cache with 7-day fallback
//! - **Graceful Fallback**: Uses expired cache during network failures
//! - **Concurrency Safe**: Prevents duplicate fetching
//!
//! ## Caching Strategy
//! 1. Uses valid cache within 24 hours
//! 2. Refreshes from remote when expired
//! 3. Falls back to stale cache (up to 7 days) on network failure

use crate::error::AuthError;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use tokio::sync::{Mutex, RwLock};

/// Global HTTP client instance with a connection pool.
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5)) // Set a 5-second timeout.
        .pool_max_idle_per_host(10) // Increase the connection pool size.
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client")
});

/// Represents a JSON Web Key (JWK).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Jwk {
    /// Key ID.
    pub kid: String,
    /// Key type (e.g., "EC").
    pub kty: String,
    /// Algorithm (e.g., "ES256").
    pub alg: Option<String>,
    /// Key usage (e.g., "sig").
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    /// Key operations.
    pub key_ops: Option<Vec<String>>,
    /// Curve (for EC keys).
    pub crv: Option<String>,
    /// X coordinate (for EC keys).
    pub x: Option<String>,
    /// Y coordinate (for EC keys).
    pub y: Option<String>,
    /// RSA modulus (for RSA keys).
    pub n: Option<String>,
    /// RSA exponent (for RSA keys).
    pub e: Option<String>,
    /// Whether the key is extractable (Supabase-specific field).
    pub ext: Option<bool>,
}

/// Represents the response from a JWKS endpoint.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwksResponse {
    /// A list of JSON Web Keys.
    pub keys: Vec<Jwk>,
}

/// Manages caching and retrieval of JWKS data from Supabase.
const JWKS_CACHE_DURATION: u64 = 24 * 3600; // 24-hour normal cache.
const JWKS_CACHE_MAX_AGE: u64 = 7 * 24 * 3600; // 7-day maximum cache for graceful fallback.

#[derive(Debug, Clone)]
pub struct JwksCache {
    /// The cached JWKS data.
    cache: Arc<RwLock<Option<JwksResponse>>>,
    /// The expiration timestamp for the normal cache.
    expires_at: Arc<RwLock<Option<u64>>>,
    /// The timestamp when the cache was created, for calculating max age.
    cached_at: Arc<RwLock<Option<u64>>>,
    /// The JWKS endpoint URL.
    jwks_url: String,
    /// A mutex to prevent concurrent fetches.
    fetch_mutex: Arc<Mutex<()>>,
}

impl JwksCache {
    /// Creates a new `JwksCache` instance.
    ///
    /// # Arguments
    ///
    /// * `jwks_url` - The Supabase JWKS endpoint URL
    pub fn new(jwks_url: &str) -> Self {
        // Basic validation: ensure HTTPS is used.
        if !jwks_url.starts_with("https://") {
            tracing::warn!("JWKS URL should use HTTPS: {}", jwks_url);
        }

        Self {
            cache: Arc::new(RwLock::new(None)),
            expires_at: Arc::new(RwLock::new(None)),
            cached_at: Arc::new(RwLock::new(None)),
            jwks_url: jwks_url.to_string(),
            fetch_mutex: Arc::new(Mutex::new(())),
        }
    }

    /// Retrieves JWKS data with graceful fallback.
    ///
    /// Uses valid cache, refreshes if expired, or falls back to stale cache on failure.
    pub async fn get_jwks(&self) -> Result<JwksResponse, AuthError> {
        self.get_jwks_with_fallback().await
    }

    /// Implements the graceful fallback logic for retrieving JWKS data.
    async fn get_jwks_with_fallback(&self) -> Result<JwksResponse, AuthError> {
        // 1. Try to use the valid cache (within 24 hours).
        if let Some(cached) = self.get_cached_jwks().await {
            tracing::debug!("Using valid cached JWKS data");
            return Ok(cached);
        }

        // 2. If the cache is expired, try to refresh it.
        match self.fetch_fresh_jwks().await {
            Ok(jwks) => {
                tracing::info!("Successfully refreshed JWKS cache");
                Ok(jwks)
            }
            Err(e) => {
                tracing::warn!("Failed to refresh JWKS, attempting fallback: {:?}", e);
                // 3. If refreshing fails, use the stale cache (up to 7 days old).
                self.get_stale_cache().await
            }
        }
    }

    /// Retrieves valid cached data (within 24 hours).
    async fn get_cached_jwks(&self) -> Option<JwksResponse> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expires_at = *self.expires_at.read().await;
        if let Some(expires) = expires_at {
            if now < expires {
                return self.cache.read().await.clone();
            }
        }
        None
    }

    /// Retrieves stale cache as fallback (up to 7 days old).
    async fn get_stale_cache(&self) -> Result<JwksResponse, AuthError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cached_at = *self.cached_at.read().await;
        if let Some(cache_time) = cached_at {
            if now - cache_time <= JWKS_CACHE_MAX_AGE {
                if let Some(cached) = self.cache.read().await.clone() {
                    tracing::warn!(
                        "Using stale JWKS cache as fallback (age: {} hours)",
                        (now - cache_time) / 3600
                    );
                    return Ok(cached);
                }
            }
        }

        let error_msg = "No valid JWKS cache available and network fetch failed";
        tracing::error!("{}", error_msg);
        Err(AuthError::JwksError(error_msg.to_string()))
    }

    /// Fetches fresh JWKS data from the remote endpoint.
    async fn fetch_fresh_jwks(&self) -> Result<JwksResponse, AuthError> {
        // Use a mutex to prevent concurrent fetches.
        let _fetch_guard = self.fetch_mutex.lock().await;

        // Double-check the cache in case it was updated while waiting for the lock.
        if let Some(cached) = self.get_cached_jwks().await {
            tracing::debug!("JWKS cache was updated while waiting for lock");
            return Ok(cached);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Fetch fresh data if the cache is expired or non-existent.
        tracing::info!("Fetching fresh JWKS from: {}", self.jwks_url);

        let response = HTTP_CLIENT.get(&self.jwks_url).send().await.map_err(|e| {
            let error_msg = format!("Failed to fetch JWKS: {e:?}");
            tracing::error!("{}", error_msg);
            AuthError::JwksError(error_msg)
        })?;

        if !response.status().is_success() {
            let error_msg = format!("JWKS endpoint returned status: {}", response.status());
            tracing::error!("{}", error_msg);
            return Err(AuthError::JwksError(error_msg));
        }

        let jwks: JwksResponse = response.json().await.map_err(|e| {
            let error_msg = format!("Failed to parse JWKS response: {e:?}");
            tracing::error!("{}", error_msg);
            AuthError::JwksError(error_msg)
        })?;

        // Basic validation: ensure there are keys.
        if jwks.keys.is_empty() {
            let error_msg = "JWKS response contains no keys";
            tracing::error!("{}", error_msg);
            return Err(AuthError::JwksError(error_msg.to_string()));
        }

        // Update the cache and timestamps.
        *self.cache.write().await = Some(jwks.clone());
        *self.expires_at.write().await = Some(now + JWKS_CACHE_DURATION);
        *self.cached_at.write().await = Some(now);

        tracing::info!(
            "JWKS cache updated, expires at: {} (cached at: {})",
            now + JWKS_CACHE_DURATION,
            now
        );
        Ok(jwks)
    }

    /// Finds a specific key by its Key ID.
    ///
    /// # Arguments
    ///
    /// * `kid` - The Key ID
    pub async fn find_key(&self, kid: &str) -> Result<Jwk, AuthError> {
        let jwks = self.get_jwks().await?;

        jwks.keys
            .iter() // Use `iter()` to avoid consuming the `Vec`.
            .find(|key| key.kid == kid)
            .cloned() // Clone only the found `Jwk`.
            .ok_or_else(|| {
                tracing::warn!("Key with kid '{}' not found in JWKS", kid);
                AuthError::NoMatchingKey
            })
    }
}

// Tests have been moved to the unified `tests` module.
// See: `src/tests/jwks_tests.rs`
