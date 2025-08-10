# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1] - 2025-08-10

### Changed
- **Optimized Dependencies**: Trimmed `reqwest` and `tokio` features to significantly reduce the library's impact on the final binary size of consumer projects. This improves performance and compile times without any breaking changes.

## [0.1.0] - YYYY-MM-DD

### Added

- Initial release of `supabase-jwt`.
- Core functionality for validating Supabase Auth JWTs.
- JWKS caching to reduce network latency.
- Asynchronous API based on `tokio`.
- Integration examples for Axum and Actix Web.
- Comprehensive test suite with over 94% coverage.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).