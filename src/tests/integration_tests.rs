//! JWT 模块集成测试
//!
//! 基于 "信任 Supabase Auth" 的核心模块协作测试
//!
//! ## 测试重点
//! - **端到端流程**：验证从 token 解析到 Claims 提取的完整流程
//! - **模块协作**：测试 Parser、JWKS、Claims 模块间的无缝集成
//! - **并发安全**：验证多线程环境下的系统稳定性
//! - **错误传播**：确保错误在模块间的正确传递和处理
//!
//! ## 简化策略
//! 专注于 Supabase Auth 标准流程：
//! - **信任源头**：假设 token 来自可信的 Supabase Auth
//! - **核心路径**：重点测试正常验证流程的稳定性
//! - **快速失败**：验证异常情况的快速识别和处理
//! - **性能验证**：确保集成后的整体性能表现
//!
//! 集成测试确保各模块协作的稳定性和效率

use super::test_helpers::*;
use crate::{claims, jwks, parser, AuthError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

// ==================== 集成测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use jsonwebtoken::{encode, Algorithm, Header};
    use p256::{ecdsa::SigningKey, pkcs8::EncodePrivateKey};
    use rand::rngs::OsRng;

    /// 端到端 “快乐路径” 集成测试 (使用有效签名)
    ///
    /// ### 测试目的
    /// 这个测试是整个 `supabase_jwt` 模块的最终健全性检查 (Sanity Check)。
    /// 它不测试加密本身，而是验证当所有外部条件（如一个有效的、由对应私钥签名的 JWT）
    /// 都满足时，我们的解析和验证流程能否正确工作。
    ///
    /// ### 设计理念
    /// 遵循 "信任 Supabase Auth，专注解析稳定性" 的原则，此测试的核心价值在于：
    /// 1.  **流程完整性验证**：覆盖从动态生成密钥、签发 JWT、模拟 JWKS 服务到最终
    ///     `Claims::from_token` 验证的完整端到端流程。
    /// 2.  **组件协作验证**：确保 `parser`、`jwks` 和 `claims` 模块无缝协作。
    /// 3.  **库使用正确性验证**：确认我们从 JWK 创建的 `DecodingKey` 能够成功验证
    ///     由 `jsonwebtoken` 和 `p256` 库生成的签名。这是对我们与底层加密库
    ///     集成的最重要保证。
    ///
    /// 如果没有这个测试，我们将缺少一个能证明“在理想情况下，代码能得出正确结果”的黄金标准。
    #[tokio::test]
    async fn test_end_to_end_jwt_validation_with_valid_signature() {
        // GIVEN: 一个动态生成的密钥对，一个基于此的 JWK，以及一个模拟 JWKS 服务
        // 1. 动态生成一个 P-256 密钥对用于测试
        let signing_key = SigningKey::random(&mut OsRng);
        let private_key_pem = signing_key.to_pkcs8_pem(Default::default()).unwrap();
        let encoding_key =
            jsonwebtoken::EncodingKey::from_ec_pem(private_key_pem.as_bytes()).unwrap();

        // 2. 从公钥创建 JWK
        let public_key = signing_key.verifying_key();
        let point = public_key.to_encoded_point(false);
        let x = general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let kid = "dynamic-e2e-test-kid";

        let jwk = jwks::Jwk {
            kid: kid.to_string(),
            kty: "EC".to_string(),
            alg: Some("ES256".to_string()),
            key_use: Some("sig".to_string()),
            key_ops: Some(vec!["verify".to_string()]),
            crv: Some("P-256".to_string()),
            x: Some(x),
            y: Some(y),
            n: None,
            e: None,
            ext: Some(true),
        };

        // 3. 设置模拟 JWKS 服务器
        let mock_server = MockServer::start().await;
        let jwks_response = jwks::JwksResponse { keys: vec![jwk] };
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_response))
            .mount(&mock_server)
            .await;

        // 4. 创建 JwksCache 和要签名的 Claims
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let jwks_cache = jwks::JwksCache::new(&jwks_url);
        let mut original_claims = create_test_claims();
        original_claims.kid = None; // kid 不应在 claims 数据中，它属于 header

        // WHEN: 使用私钥签发一个 JWT，然后使用我们的库来验证它
        // 5. 创建并签发 JWT
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        let token = encode(&header, &original_claims, &encoding_key)
            .expect("Failed to sign JWT with dynamic key");

        // 6. 使用库的核心功能来验证 token
        let validated_claims = claims::Claims::from_token(&token, &jwks_cache)
            .await
            .expect("JWT validation should succeed for a token signed with a valid key");

        // THEN: 验证后的 Claims 应该与原始 Claims 完全一致
        // 7. 全面验证 Claims 的所有字段
        assert_eq!(
            validated_claims.sub, original_claims.sub,
            "User ID (sub) should match"
        );
        assert_eq!(
            validated_claims.exp, original_claims.exp,
            "Expiration time (exp) should match"
        );
        assert_eq!(
            validated_claims.iat, original_claims.iat,
            "Issued at (iat) should match"
        );
        assert_eq!(
            validated_claims.jti, original_claims.jti,
            "JWT ID (jti) should match"
        );
        assert_eq!(
            validated_claims.email, original_claims.email,
            "Email should match"
        );
        assert_eq!(
            validated_claims.phone, original_claims.phone,
            "Phone should match"
        );
        assert_eq!(
            validated_claims.role, original_claims.role,
            "Role should match"
        );
        assert_eq!(
            validated_claims.app_metadata, original_claims.app_metadata,
            "App metadata should match"
        );
        assert_eq!(
            validated_claims.user_metadata, original_claims.user_metadata,
            "User metadata should match"
        );
        assert_eq!(
            validated_claims.aud, original_claims.aud,
            "Audience (aud) should match"
        );
        assert_eq!(
            validated_claims.iss, original_claims.iss,
            "Issuer (iss) should match"
        );
        assert_eq!(
            validated_claims.aal, original_claims.aal,
            "Authentication Assurance Level (aal) should match"
        );
        assert_eq!(
            validated_claims.amr, original_claims.amr,
            "Authentication Methods References (amr) should match"
        );
        assert_eq!(
            validated_claims.session_id, original_claims.session_id,
            "Session ID should match"
        );
        assert_eq!(
            validated_claims.is_anonymous, original_claims.is_anonymous,
            "Anonymous status should match"
        );

        // 8. 验证 kid 是否已从 header 正确填充到 Claims 结构体中
        assert_eq!(
            validated_claims.kid.as_deref(),
            Some(kid),
            "Key ID (kid) should be correctly populated from the JWT header"
        );
    }

    /// 端到端 “悲伤路径” 集成测试 (使用无效签名)
    ///
    /// ### 测试目的
    /// 这个测试验证了当提供一个格式正确但签名无效的 JWT 时，
    /// 我们的验证流程能够正确地在最后一步（签名验证）失败。
    ///
    /// ### 设计理念
    /// 它补充了 `test_end_to_end_jwt_validation_with_valid_signature` 测试，
    /// 共同确保了端到端流程的完整性：
    /// 1.  **快乐路径 (Happy Path)**：验证有效 token 能成功通过。
    /// 2.  **悲伤路径 (Sad Path)**：验证无效 token 会在正确环节失败。
    ///
    /// 此测试使用了 `create_mock_jwt_token` 辅助函数，该函数专门生成一个
    /// 具有无效签名的 token，以模拟真实世界中可能遇到的伪造或损坏的 token。
    #[tokio::test]
    async fn test_end_to_end_validation_with_invalid_signature() {
        // GIVEN: 一个模拟的 JWKS 服务和一个带有无效签名的模拟 JWT
        // 1. 设置模拟 JWKS 服务器
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let jwks_cache = jwks::JwksCache::new(&jwks_url);

        // 2. 创建一个 header 和 payload 都正确，但签名无效的模拟 JWT token
        let token = create_mock_jwt_token();

        // WHEN: 尝试通过完整的解析和验证流程
        // 3. 解析 JWT header (应该成功)
        let header =
            parser::JwtParser::decode_header(&token).expect("Should decode header successfully");

        // 4. 从 JWKS 获取密钥 (应该成功)
        let jwk = jwks_cache
            .find_key(header.kid.as_ref().unwrap())
            .await
            .expect("Should find key in JWKS");

        // 5. 创建解码密钥 (应该成功)
        let decoding_key =
            parser::JwtParser::create_decoding_key(&jwk).expect("Should create decoding key");

        // 6. 解析算法 (应该成功)
        let algorithm =
            parser::JwtParser::parse_algorithm(&header.alg).expect("Should parse algorithm");

        // THEN: 验证流程应该在最后一步签名验证时失败，并返回 `Verification` 错误
        // 7. 验证和解码 token (预期会因签名无效而失败)
        let result = parser::JwtParser::verify_and_decode(&token, &decoding_key, algorithm);
        assert!(
            result.is_err(),
            "Validation should fail for mock token with invalid signature"
        );

        // 8. 验证错误类型是否为 `AuthError::Verification`
        // 这证明了整个流程（解析、密钥获取、验证）是连贯的，并在正确的环节失败
        match result {
            Err(AuthError::Verification) => {
                // 这是预期的结果，证明签名验证逻辑按预期工作
            }
            Err(e) => {
                panic!(
                    "Expected a verification error due to invalid signature, but got: {:?}",
                    e
                );
            }
            Ok(_) => {
                panic!("Validation should have failed for an invalid signature, but it passed");
            }
        }
    }

    /// 测试错误处理的集成
    #[tokio::test]
    async fn test_error_handling_integration() {
        // 测试无效 token 的完整流程
        let invalid_token = "invalid.jwt.token";

        let result = parser::JwtParser::decode_header(invalid_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::DecodeHeader));
    }

    /// 测试 JWKS 缓存的并发访问
    #[tokio::test]
    async fn test_jwks_concurrent_access() {
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let jwks_cache = Arc::new(jwks::JwksCache::new(&jwks_url));

        let mut join_set = JoinSet::new();

        // 并发测试 JWKS 操作
        for _i in 0..5 {
            let jwks_clone = jwks_cache.clone();

            join_set.spawn(async move {
                // 测试 JWKS 操作
                let jwks_result = jwks_clone.get_jwks().await;
                assert!(jwks_result.is_ok());

                // 测试密钥查找
                let key_result = jwks_clone.find_key("test-key-id").await;
                assert!(key_result.is_ok());

                jwks_result.is_ok()
            });
        }

        // 验证所有操作都成功
        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            results.push(result.unwrap());
        }

        assert_eq!(results.len(), 5);
        for jwks_ok in results {
            assert!(jwks_ok);
        }
    }

    /// 测试 Claims 模块的集成验证
    /// 验证 Claims 与其他模块的协作和数据完整性
    #[tokio::test]
    async fn test_claims_module_integration() {
        // 1. 创建测试 Claims
        let claims = create_test_claims();

        // 2. 验证 Claims 的基本功能
        assert_eq!(claims.user_id(), TEST_USER_ID);
        assert_eq!(claims.email(), Some(TEST_EMAIL));
        assert_eq!(claims.role(), "authenticated");
        assert!(!claims.is_anonymous());

        // 3. 验证安全性检查
        assert!(claims.validate_security().is_ok());

        // 4. 验证元数据访问
        let name: Option<String> = claims.get_user_metadata("name");
        assert_eq!(name, Some("Test User".to_string()));

        let provider: Option<String> = claims.get_app_metadata("provider");
        assert_eq!(provider, Some("email".to_string()));

        // 5. 验证序列化/反序列化的完整性
        let serialized = serde_json::to_string(&claims).expect("Should serialize successfully");
        let deserialized: claims::Claims =
            serde_json::from_str(&serialized).expect("Should deserialize successfully");

        // 验证反序列化后的数据完整性
        assert_eq!(deserialized.user_id(), claims.user_id());
        assert_eq!(deserialized.email(), claims.email());
        assert_eq!(deserialized.role(), claims.role());
        assert_eq!(deserialized.is_anonymous(), claims.is_anonymous());
    }

    /// 测试 Claims 的并发安全性
    /// 验证多线程环境下 Claims 访问的线程安全
    #[tokio::test]
    async fn test_claims_concurrent_safety() {
        let claims = Arc::new(create_test_claims());
        let mut join_set = JoinSet::new();

        // 并发测试 Claims 的各种访问方法
        for i in 0..10 {
            let claims_clone = claims.clone();

            join_set.spawn(async move {
                // 测试基本字段访问
                let user_id = claims_clone.user_id();
                let email = claims_clone.email();
                let role = claims_clone.role();
                let is_anonymous = claims_clone.is_anonymous();

                // 测试元数据访问
                let name: Option<String> = claims_clone.get_user_metadata("name");
                let provider: Option<String> = claims_clone.get_app_metadata("provider");

                // 测试安全性验证
                let security_ok = claims_clone.validate_security().is_ok();

                // 验证所有访问都返回一致的结果
                (
                    user_id == TEST_USER_ID,
                    email == Some(TEST_EMAIL),
                    role == "authenticated",
                    !is_anonymous,
                    name == Some("Test User".to_string()),
                    provider == Some("email".to_string()),
                    security_ok,
                    i,
                )
            });
        }

        // 收集所有结果并验证一致性
        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            results.push(result.unwrap());
        }

        assert_eq!(results.len(), 10);
        for (user_id_ok, email_ok, role_ok, not_anonymous, name_ok, provider_ok, security_ok, _) in
            results
        {
            assert!(user_id_ok, "User ID should be consistent across threads");
            assert!(email_ok, "Email should be consistent across threads");
            assert!(role_ok, "Role should be consistent across threads");
            assert!(
                not_anonymous,
                "Anonymous status should be consistent across threads"
            );
            assert!(name_ok, "User metadata should be consistent across threads");
            assert!(
                provider_ok,
                "App metadata should be consistent across threads"
            );
            assert!(
                security_ok,
                "Security validation should be consistent across threads"
            );
        }
    }

    /// 性能验证测试 - Claims 序列化/反序列化性能
    /// 确保集成后的整体性能表现符合要求
    #[tokio::test]
    async fn test_claims_serialization_performance() {
        let claims = create_test_claims();
        let iterations = 1000;

        // 测试序列化性能
        let start = Instant::now();
        for _ in 0..iterations {
            let _serialized =
                serde_json::to_string(&claims).expect("Serialization should not fail");
        }
        let serialization_duration = start.elapsed();

        // 序列化性能应该在合理范围内（每次操作 < 1ms）
        let avg_serialization_time = serialization_duration / iterations;
        assert!(
            avg_serialization_time < Duration::from_millis(1),
            "Serialization too slow: {:?} per operation",
            avg_serialization_time
        );

        // 测试反序列化性能
        let serialized = serde_json::to_string(&claims).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            let _deserialized: claims::Claims =
                serde_json::from_str(&serialized).expect("Deserialization should not fail");
        }
        let deserialization_duration = start.elapsed();

        // 反序列化性能应该在合理范围内（每次操作 < 2ms）
        let avg_deserialization_time = deserialization_duration / iterations;
        assert!(
            avg_deserialization_time < Duration::from_millis(2),
            "Deserialization too slow: {:?} per operation",
            avg_deserialization_time
        );

        println!(
            "Performance metrics - Serialization: {:?}/op, Deserialization: {:?}/op",
            avg_serialization_time, avg_deserialization_time
        );
    }

    /// 性能验证测试 - 端到端流程性能
    /// 测试完整 JWT 验证流程的性能表现
    #[tokio::test]
    async fn test_end_to_end_performance() {
        // 设置模拟 JWKS 服务器
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let jwks_cache = jwks::JwksCache::new(&jwks_url);

        // 预热 JWKS 缓存
        let _ = jwks_cache.get_jwks().await;

        let token = create_mock_jwt_token();
        let iterations = 100;

        // 测试端到端流程性能
        let start = Instant::now();
        for _ in 0..iterations {
            // 解析 JWT header
            let header = parser::JwtParser::decode_header(&token);
            if let Ok(header) = header {
                // 从 JWKS 获取密钥（使用缓存）
                if let Some(kid) = header.kid {
                    let _ = jwks_cache.find_key(&kid).await;
                }
            }
        }
        let total_duration = start.elapsed();

        // 端到端流程性能应该在合理范围内（每次操作 < 10ms）
        let avg_operation_time = total_duration / iterations;
        assert!(
            avg_operation_time < Duration::from_millis(10),
            "End-to-end operation too slow: {:?} per operation",
            avg_operation_time
        );

        println!(
            "End-to-end performance: {:?}/op for {} iterations",
            avg_operation_time, iterations
        );
    }

    /// 测试 Claims 与 Parser、JWKS 模块的完整集成
    /// 验证三个核心模块间的无缝协作
    #[tokio::test]
    async fn test_complete_module_integration() {
        // 1. 设置 JWKS 环境
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let jwks_cache = jwks::JwksCache::new(&jwks_url);

        // 2. 创建测试 token 和 Claims
        let token = create_mock_jwt_token();
        let test_claims = create_test_claims();

        // 3. 测试 Parser 模块
        let header_result = parser::JwtParser::decode_header(&token);
        assert!(
            header_result.is_ok(),
            "Parser should decode header successfully"
        );

        let header = header_result.unwrap();
        assert!(header.kid.is_some(), "Header should contain kid");

        // 4. 测试 JWKS 模块
        let jwk_result = jwks_cache.find_key(header.kid.as_ref().unwrap()).await;
        assert!(jwk_result.is_ok(), "JWKS should find key successfully");

        // 5. 测试 Claims 模块的数据完整性
        assert!(
            test_claims.validate_security().is_ok(),
            "Claims should pass security validation"
        );
        assert_eq!(
            test_claims.user_id(),
            TEST_USER_ID,
            "Claims should provide correct user ID"
        );

        // 6. 验证模块间的错误传播
        let invalid_token = "invalid.jwt.token";
        let invalid_header_result = parser::JwtParser::decode_header(invalid_token);
        assert!(
            invalid_header_result.is_err(),
            "Parser should reject invalid token"
        );
        assert!(matches!(
            invalid_header_result.unwrap_err(),
            AuthError::DecodeHeader
        ));

        // 7. 测试并发环境下的模块协作
        let mut join_set = JoinSet::new();
        for _ in 0..5 {
            let jwks_clone = Arc::new(jwks_cache.clone());
            let claims_clone = test_claims.clone();
            let token_clone = token.clone();

            join_set.spawn(async move {
                // 并发测试各模块的协作
                let header = parser::JwtParser::decode_header(&token_clone)?;
                let _jwk = jwks_clone.find_key(header.kid.as_ref().unwrap()).await?;
                claims_clone.validate_security()?;
                Ok::<(), AuthError>(())
            });
        }

        // 验证所有并发操作都成功
        let mut concurrent_results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            concurrent_results.push(result.unwrap());
        }

        assert_eq!(concurrent_results.len(), 5);
        for result in concurrent_results {
            assert!(
                result.is_ok(),
                "Concurrent module integration should succeed"
            );
        }
    }
}
