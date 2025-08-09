//! 共享测试辅助函数和常量
//!
//! 基于 "信任 Supabase Auth，简化测试数据" 的设计理念
//!
//! ## 核心功能
//! - **标准化测试数据**：提供一致的 Claims、JWK 和 token 模拟数据
//! - **高效模拟服务**：使用 wiremock 创建轻量级的 JWKS 服务器
//! - **简化测试流程**：减少重复代码，提高测试编写效率
//! - **可信数据源**：模拟符合 Supabase Auth 标准的测试数据
//!
//! ## 设计原则
//! - **最小化复杂性**：避免过度复杂的测试数据生成
//! - **标准化格式**：确保测试数据符合 Supabase Auth 规范
//! - **高效重用**：提供可复用的辅助函数和常量
//! - **快速验证**：支持快速的单元测试和集成测试
//!
//! 测试辅助工具专注于提供简洁、高效的测试支持

use crate::{claims, jwks};

// 重新导出常用类型和常量
pub use serde_json::json;
pub use std::time::{SystemTime, UNIX_EPOCH};
pub use wiremock::{Mock, MockServer, ResponseTemplate};

// ==================== 测试常量 ====================

/// 测试用户ID
pub const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

/// 测试邮箱
pub const TEST_EMAIL: &str = "test@example.com";

/// 测试电话号码
pub const TEST_PHONE: &str = "+1234567890";

/// 测试会话ID
pub const TEST_SESSION_ID: &str = "test-session-id";

/// 测试签发者
pub const TEST_ISSUER: &str = "https://test.supabase.co/auth/v1";

/// 测试密钥ID
pub const TEST_KID: &str = "test-key-id";

/// 测试JWKS URL
pub const TEST_JWKS_URL: &str = "https://test.supabase.co/auth/v1/jwks";

// ==================== Claims 辅助函数 ====================

/// 创建标准测试用的 Claims
///
/// # 返回
/// 包含完整字段的有效 Claims 对象
pub fn create_test_claims() -> claims::Claims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    claims::Claims {
        sub: TEST_USER_ID.to_string(),
        exp: now + 3600, // 1小时后过期
        iat: Some(now),
        jti: Some("test-jti".to_string()),
        email: Some(TEST_EMAIL.to_string()),
        phone: Some(TEST_PHONE.to_string()),
        role: Some("authenticated".to_string()),
        app_metadata: Some(json!({"provider": "email"})),
        user_metadata: Some(json!({"name": "Test User"})),
        aud: Some("authenticated".to_string()),
        iss: Some(TEST_ISSUER.to_string()),
        aal: Some("aal1".to_string()),
        amr: Some(vec![json!({"method": "password"})]),
        session_id: Some(TEST_SESSION_ID.to_string()),
        is_anonymous: Some(false),
        kid: Some(TEST_KID.to_string()),
    }
}

/// 创建最小化的 Claims（仅包含必需字段）
///
/// # 返回
/// 仅包含必需字段的 Claims 对象
pub fn create_minimal_claims() -> claims::Claims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    claims::Claims {
        sub: TEST_USER_ID.to_string(),
        exp: now + 3600,
        iat: None,
        jti: None,
        email: None,
        phone: None,
        role: None,
        app_metadata: None,
        user_metadata: None,
        aud: None,
        iss: None,
        aal: None,
        amr: None,
        session_id: None,
        is_anonymous: None,
        kid: None,
    }
}

// ==================== JWKS 辅助函数 ====================

/// 创建测试用的 JWK (public key)
///
/// # 返回
/// 标准的 ES256 JWK 对象
pub fn create_test_jwk() -> jwks::Jwk {
    jwks::Jwk {
        kid: TEST_KID.to_string(),
        kty: "EC".to_string(),
        alg: Some("ES256".to_string()),
        key_use: Some("sig".to_string()),
        key_ops: Some(vec!["verify".to_string()]),
        crv: Some("P-256".to_string()),
        x: Some("ykCi3ZomyYBFS21ZKk6ajc56O1SUFzhCNp0ziDYd6mw".to_string()),
        y: Some("okXySUHOrPVxWBr0HlCw4yWY_TMq8EyhKhTugGoRCQU".to_string()),
        n: None,
        e: None,
        ext: Some(true),
    }
}

/// 创建测试用的 JWKS 响应
///
/// # 返回
/// 包含测试 JWK 的 JWKS 响应
pub fn create_test_jwks_response() -> jwks::JwksResponse {
    jwks::JwksResponse {
        keys: vec![create_test_jwk()],
    }
}

/// 创建空的 JWKS 响应
///
/// # 返回
/// 不包含任何密钥的 JWKS 响应
pub fn create_empty_jwks_response() -> jwks::JwksResponse {
    jwks::JwksResponse { keys: vec![] }
}

// ==================== JWT Token 辅助函数 ====================

/// 创建一个模拟的 JWT token（仅用于 header 解析测试）
///
/// ⚠️ 重要限制：
/// - 这个 token 的签名是无效的，仅用于测试 header 解析功能
/// - 不能用于完整的 JWT 验证测试
/// - 不能用于端到端的认证流程测试
/// - 建议在集成测试中使用真实的 Supabase Auth JWT
///
/// # 返回
/// 格式正确但签名无效的 JWT token 字符串，包含真实的 Supabase Auth 格式
pub fn create_mock_jwt_token() -> String {
    // 真实的 Supabase Auth JWT header 格式
    // {"alg":"ES256","typ":"JWT","kid":"test-key-id"}
    let header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LWlkIn0";

    // 真实的 Supabase Auth JWT payload 格式
    // {
    //   "sub": "550e8400-e29b-41d4-a716-446655440000",
    //   "aud": "authenticated",
    //   "role": "authenticated",
    //   "email": "test@example.com",
    //   "iss": "https://test.supabase.co/auth/v1",
    //   "iat": 1640995200,
    //   "exp": 9999999999
    // }
    let payload = "eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwicm9sZSI6ImF1dGhlbnRpY2F0ZWQiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJpc3MiOiJodHRwczovL3Rlc3Quc3VwYWJhc2UuY28vYXV0aC92MSIsImlhdCI6MTY0MDk5NTIwMCwiZXhwIjo5OTk5OTk5OTk5fQ";

    // 无效但格式正确的 base64url 签名（仅用于测试）
    // 注意：真实环境中需要使用有效的 ES256 签名
    let signature = "MOCK_SIGNATURE_FOR_TESTING_ONLY_NOT_VALID";

    format!("{header}.{payload}.{signature}")
}

// ==================== Mock Server 辅助函数 ====================

/// 创建测试用的 Mock JWKS Server
///
/// # 返回
/// 配置好的 MockServer 实例
pub async fn create_mock_jwks_server() -> MockServer {
    let mock_server = MockServer::start().await;
    let jwks_response = create_test_jwks_response();

    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_response))
        .mount(&mock_server)
        .await;

    mock_server
}

/// 创建返回错误的 Mock JWKS Server
///
/// # 返回
/// 返回 500 错误的 MockServer 实例
pub async fn create_error_mock_jwks_server() -> MockServer {
    let mock_server = MockServer::start().await;

    Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/jwks"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    mock_server
}
