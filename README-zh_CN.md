# supabase-jwt

[![Crates.io](https://img.shields.io/crates/v/supabase-jwt.svg)](https://crates.io/crates/supabase-jwt)
[![Docs.rs](https://docs.rs/supabase-jwt/badge.svg)](https://docs.rs/supabase-jwt)
[![Build Status](https://img.shields.io/github/actions/workflow/status/supabase-community/supabase-jwt-rs/ci.yml?branch=main)](https://github.com/supabase-community/supabase-jwt-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/supabase-jwt.svg)](https://github.com/supabase-community/supabase-jwt-rs/blob/main/LICENSE-MIT)

[English](README.md) | 简体中文

一个轻量级、框架无关的 Rust 库，用于验证 Supabase Auth JWT 令牌，支持 JWKS 缓存。

## 目录

- [✨ 特性](#-特性)
- [🚀 快速开始](#-快速开始)
- [🔧 安装](#-安装)
- [🧩 框架集成示例](#-框架集成示例)
  - [Axum](#axum)
  - [Actix Web](#actix-web)
- [📖 API 概览](#-api-概览)
- [🏛️ 设计理念](#️-设计理念)
- [✅ 测试与质量](#-测试与质量)
- [🤝 贡献](#-贡献)
- [📜 许可证](#-许可证)

## ✨ 特性

- 🚀 **高性能**: 智能 JWKS 缓存，减少网络请求。
- 🔒 **安全**: 专为 Supabase Auth ES256 算法优化。
- 🎯 **简洁**: 框架无关，API 设计简单，易于集成。
- ⚡ **异步**: 基于 `tokio` 的纯异步设计。
- 🛡️ **可靠**: 经过充分测试，代码覆盖率 >94%。

## 🚀 快速开始

```rust
use supabase_jwt::{Claims, JwksCache};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 初始化 JWKS 缓存
    // 从你的 Supabase 项目 API 设置中获取 URL
    let jwks_url = "https://<your-project-ref>.supabase.co/auth/v1/jwks";
    let jwks_cache = JwksCache::new(jwks_url);
    
    // 2. 从请求中获取 Bearer Token
    let bearer_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."; // 从 Authorization 头获取
    
    // 3. 验证 JWT 并提取 Claims
    // from_bearer_token 会自动处理 "Bearer " 前缀
    match Claims::from_bearer_token(bearer_token, &jwks_cache).await {
        Ok(claims) => {
            // 4. 访问用户信息
            println!("用户 ID: {}", claims.user_id());
            println!("邮箱: {:?}", claims.email());
            println!("角色: {}", claims.role());
            println!("授权于: {}", claims.issued_at());
            println!("过期于: {}", claims.expires_at());
        }
        Err(e) => {
            eprintln!("Token 验证失败: {:?}", e);
        }
    }
    
    Ok(())
}
```

## 🔧 安装

在你的 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
supabase-jwt = "0.1.0" # 请在 crates.io 上检查最新版本
tokio = { version = "1.47.0", features = ["full"] }
```

## 🧩 框架集成示例

### Axum

推荐使用 `axum-extra` 来优雅地提取 Bearer Token。

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
// 在你的应用中设置状态
async fn run_app() {
    let jwks_cache = Arc::new(JwksCache::new("..."));
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .with_state(jwks_cache);
    
    // 启动服务器...
}
*/
```

### Actix Web

在 Actix Web 中，你可以从请求头中手动提取。

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

## 📖 API 概览

`Claims` 结构体提供了便捷的方法来访问 JWT 中的标准和自定义信息。

```rust
// 基本信息
let user_id = claims.user_id();        // 用户 ID (sub)
let email = claims.email();            // 邮箱 (email)
let role = claims.role();              // 角色 (role)
let phone = claims.phone();            // 手机号 (phone)
let is_anon = claims.is_anonymous();   // 是否为匿名用户 (is_anonymous)

// 时间戳
let issued_at = claims.issued_at();    // 颁发时间 (iat)
let expires_at = claims.expires_at();  // 过期时间 (exp)

// 元数据
// 假设 user_metadata = {"custom_field": "value"}
let custom_field: Option<String> = claims.get_user_metadata("custom_field");

// 假设 app_metadata = {"feature_enabled": true}
let app_setting: Option<bool> = claims.get_app_metadata("feature_enabled");
```

`JwksCache` 提供了智能的密钥缓存机制来高效验证令牌。

```rust
let jwks_cache = JwksCache::new("https://<project>.supabase.co/auth/v1/jwks");

// 自动从缓存或网络获取 JWKS
let jwks = jwks_cache.get_jwks().await?;

// 查找特定密钥（通常由 from_token 内部调用）
let key = jwks_cache.find_key("key_id").await?;
```

更多详细信息，请参阅 [**docs.rs 上的完整 API 文档**](https://docs.rs/supabase-jwt)。

## 🚀 高级用法

### 错误处理

优雅地处理不同的认证错误是一种良好的实践。`from_bearer_token` 会返回一个详细的 `AuthError` 枚举。

```rust
use supabase_jwt::{AuthError, Claims, JwksCache};

async fn handle_request(bearer_token: &str, jwks_cache: &JwksCache) {
    match Claims::from_bearer_token(bearer_token, jwks_cache).await {
        Ok(claims) => {
            println!("成功为用户 {} 验证令牌", claims.user_id());
        }
        Err(e) => {
            eprintln!("认证失败: {}", e);
            // 处理特定错误的示例
            match e {
                AuthError::InvalidToken => {
                    // 触发重新认证
                }
                AuthError::Verification => {
                    // 令牌签名无效，可能存在安全风险
                }
                AuthError::JwksError(_) => {
                    // 可能是网络问题或 Supabase 服务中断
                }
                _ => {
                    // 处理其他情况
                }
            }
        }
    }
}
```

### 缓存行为

`JwksCache` 专为高可用性和高性能而设计，内置了智能缓存策略，无需手动配置：

- **正常缓存**：JWKS 的缓存时间为 **24 小时**。
- **降级缓存**：如果获取新密钥失败（例如，由于网络错误），缓存将继续提供最后一次已知的有效密钥，最长可达 **7 天**。这可以防止您的应用程序在 Supabase Auth 服务暂时不可用时完全失效。
- **网络超时**：所有到 JWKS 端点的网络请求都有 **5 秒** 的超时设置，以防止您的应用程序被挂起。


## 🏛️ 设计理念

本库基于 "信任 Supabase Auth，专注解析稳定性" 的设计理念：

- **信任上游**: 相信 Supabase Auth 生成的 token 格式和内容的合法性。
- **专注解析**: 重点保证解析过程的稳定性和性能。
- **快速失败**: 对异常 token 立即拒绝，避免过度验证。
- **缓存优化**: 智能 JWKS 缓存，减少网络开销。

## ✅ 测试与质量

我们非常重视代码质量和可靠性，并通过全面的测试策略来保证。

- **测试覆盖率**: 使用 `cargo-tarpaulin` 达到 **94%+** 的代码覆盖率。
- **测试用例**: 超过 **100个** 测试用例，覆盖了核心逻辑、边界条件和集成场景。
- **模拟服务**: 使用 `wiremock` 模拟 Supabase Auth API，确保测试的稳定性和独立性。

你可以使用以下命令运行测试：
```bash
# 运行所有测试
cargo test

# 计算代码覆盖率
cargo tarpaulin --include-tests
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！在贡献代码前，请确保：

1. 运行 `cargo fmt` 格式化代码。
2. 运行 `cargo clippy` 检查代码质量。
3. 运行 `cargo test` 确保所有测试通过。

## 📜 许可证

本项目采用 MIT 或 Apache-2.0 双重许可证。详见 [LICENSE-MIT](LICENSE-MIT) 和 [LICENSE-APACHE](LICENSE-APACHE) 文件。
