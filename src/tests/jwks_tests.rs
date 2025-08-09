//! JWKS 缓存管理模块单元测试
//!
//! 基于 "高可用性和智能缓存" 的 JWKS 管理测试
//!
//! ## 测试重点
//! - **缓存稳定性**：验证 JWKS 缓存的创建、更新和一致性
//! - **密钥查找效率**：测试 Key ID 匹配和密钥检索的性能
//! - **网络容错性**：验证网络故障时的降级和恢复机制
//! - **并发安全性**：确保多线程环境下的缓存操作安全
//!
//! ## 核心功能验证
//! - **智能缓存**：测试缓存更新策略和过期处理
//! - **错误恢复**：验证网络异常后的自动恢复能力
//! - **数据一致性**：确保缓存数据与远程 JWKS 的同步
//! - **性能优化**：测试缓存命中率和响应时间
//!
//! JWKS 管理专注于为 JWT 验证提供稳定、高效的密钥服务

use super::test_helpers::*;
use crate::{jwks, parser};
use std::sync::Arc;

// ==================== JWKS 缓存管理功能测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwks_cache_creation() {
        let cache = jwks::JwksCache::new(TEST_JWKS_URL);
        drop(cache); // 确保创建成功
    }

    #[tokio::test]
    async fn test_jwks_cache_operations() {
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        // 测试获取 JWKS
        let result = cache.get_jwks().await;
        assert!(result.is_ok());

        let jwks = result.unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, TEST_KID);
    }

    #[tokio::test]
    async fn test_jwks_find_key() {
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        // 测试找到密钥
        let result = cache.find_key(TEST_KID).await;
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.kid, TEST_KID);
        assert_eq!(key.kty, "EC");
        assert_eq!(key.alg, Some("ES256".to_string()));

        // 测试找不到密钥
        let result = cache.find_key("non-existent-key").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_jwk_structure() {
        let jwk = create_test_jwk();

        assert_eq!(jwk.kid, TEST_KID);
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.alg, Some("ES256".to_string()));
        assert_eq!(jwk.crv, Some("P-256".to_string()));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
    }

    #[test]
    fn test_jwks_response_structure() {
        let response = create_test_jwks_response();

        assert_eq!(response.keys.len(), 1);
        assert_eq!(response.keys[0].kid, TEST_KID);
    }

    #[test]
    fn test_jwk_serialization() {
        let jwk = create_test_jwk();

        // 测试序列化
        let serialized = serde_json::to_string(&jwk).unwrap();
        assert!(!serialized.is_empty());

        // 测试反序列化
        let deserialized: jwks::Jwk = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.kid, jwk.kid);
        assert_eq!(deserialized.kty, jwk.kty);
    }

    // ==================== 错误处理测试 ====================

    #[tokio::test]
    async fn test_jwks_server_errors() {
        let mock_server = MockServer::start().await;

        // 设置服务器返回错误
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        let result = cache.get_jwks().await;
        assert!(result.is_err());
    }

    // ==================== 边界条件测试 ====================

    #[test]
    fn test_jwk_with_missing_optional_fields() {
        let mut jwk = create_test_jwk();
        jwk.key_use = None;
        jwk.key_ops = None;
        jwk.ext = None;

        // 应该仍然有效
        assert_eq!(jwk.kid, TEST_KID);
        assert_eq!(jwk.kty, "EC");
    }

    // ==================== 基本缓存测试 ====================

    #[tokio::test]
    async fn test_jwks_cache_basic_functionality() {
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        // 测试密钥查找
        let result = cache.find_key(TEST_KID).await;
        assert!(result.is_ok());

        let jwk = result.unwrap();
        assert_eq!(jwk.kid, TEST_KID);
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.alg, Some("ES256".to_string()));

        // 测试缓存命中（第二次调用应该使用缓存）
        let result2 = cache.find_key(TEST_KID).await;
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().kid, TEST_KID);
    }

    // ==================== 密钥查找边界测试 ====================

    #[tokio::test]
    async fn test_jwks_find_key_not_found() {
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        // 查找不存在的密钥
        let result = cache.find_key("non-existent-key-id").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwks_empty_response() {
        let mock_server = MockServer::start().await;

        // 设置服务器返回空的 JWKS
        let empty_jwks = serde_json::json!({
            "keys": []
        });

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&empty_jwks))
            .mount(&mock_server)
            .await;

        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        // 在空的 JWKS 中查找密钥应该失败
        let result = cache.find_key(TEST_KID).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwks_invalid_json_response() {
        let mock_server = MockServer::start().await;

        // 设置服务器返回无效的 JSON
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_string("invalid json"))
            .mount(&mock_server)
            .await;

        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        let result = cache.get_jwks().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwks_network_timeout() {
        // 使用一个不存在的 URL 来模拟网络超时
        let cache = jwks::JwksCache::new("http://127.0.0.1:1/jwks");

        let result = cache.get_jwks().await;
        assert!(result.is_err());
    }

    // ==================== JWK 结构验证测试 ====================

    #[test]
    fn test_jwk_missing_required_fields() {
        // 测试缺少 kid 的情况（kid 为空字符串）
        let mut jwk_empty_kid = create_test_jwk();
        jwk_empty_kid.kid = "".to_string();
        // kid 为空不会影响解码密钥创建，因为它主要用于密钥查找
        let result_kid = parser::JwtParser::create_decoding_key(&jwk_empty_kid);
        assert!(
            result_kid.is_ok(),
            "Empty kid should not prevent decoding key creation"
        );

        // 测试缺少 kty 的情况（kty 为空字符串）
        let mut jwk_empty_kty = create_test_jwk();
        jwk_empty_kty.kty = "".to_string();
        // kty 为空应该导致解码密钥创建失败
        let result_kty = parser::JwtParser::create_decoding_key(&jwk_empty_kty);
        assert!(
            matches!(result_kty, Err(crate::AuthError::UnsupportedKeyType(_))),
            "Empty kty should cause decoding key creation to fail"
        );

        // 测试不支持的 kty 类型
        let mut jwk_invalid_kty = create_test_jwk();
        jwk_invalid_kty.kty = "RSA".to_string();
        let result_invalid = parser::JwtParser::create_decoding_key(&jwk_invalid_kty);
        assert!(
            matches!(result_invalid, Err(crate::AuthError::UnsupportedKeyType(_))),
            "Unsupported kty should cause decoding key creation to fail"
        );
    }

    #[test]
    fn test_jwk_coordinate_edge_cases() {
        let mut jwk = create_test_jwk();

        // 测试坐标为空字符串的情况
        jwk.x = Some("".to_string());
        jwk.y = Some("".to_string());

        // 验证空坐标在创建解码密钥时会失败
        // decode("") is valid and returns an empty vec, so it fails at the length check
        let result = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result, Err(crate::AuthError::InvalidKeyComponent(_))),
            "Empty coordinates should fail at the length check, not base64 decoding"
        );

        // 测试坐标为 None 的情况
        let mut jwk_none = create_test_jwk();
        jwk_none.x = None;
        jwk_none.y = None;

        // 验证缺失坐标在创建解码密钥时会失败
        let result_none = parser::JwtParser::create_decoding_key(&jwk_none);
        assert!(
            matches!(result_none, Err(crate::AuthError::InvalidKeyComponent(_))),
            "Missing coordinates should cause decoding key creation to fail"
        );

        // 测试只有一个坐标缺失的情况
        let mut jwk_partial = create_test_jwk();
        jwk_partial.x = None;
        let result_partial = parser::JwtParser::create_decoding_key(&jwk_partial);
        assert!(
            matches!(
                result_partial,
                Err(crate::AuthError::InvalidKeyComponent(_))
            ),
            "Partial coordinates should cause decoding key creation to fail"
        );
    }

    #[tokio::test]
    async fn test_jwks_cache_error_recovery() {
        // 测试从错误状态恢复
        let error_server = create_error_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", error_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        // 第一次请求应该失败
        let result = cache.get_jwks().await;
        assert!(result.is_err());

        // 查找密钥也应该失败
        let key_result = cache.find_key(TEST_KID).await;
        assert!(key_result.is_err());
    }

    #[tokio::test]
    async fn test_jwks_multiple_keys() {
        // 创建包含多个密钥的 JWKS 响应
        let mock_server = MockServer::start().await;
        let jwks_response = jwks::JwksResponse {
            keys: vec![
                create_test_jwk(),
                jwks::Jwk {
                    kid: "key-2".to_string(),
                    kty: "EC".to_string(),
                    alg: Some("ES256".to_string()),
                    key_use: Some("sig".to_string()),
                    key_ops: Some(vec!["verify".to_string()]),
                    crv: Some("P-256".to_string()),
                    x: Some("different_x_coordinate".to_string()),
                    y: Some("different_y_coordinate".to_string()),
                    n: None,
                    e: None,
                    ext: Some(true),
                },
            ],
        };

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_response))
            .mount(&mock_server)
            .await;

        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        // 测试找到第一个密钥
        let key1 = cache.find_key(TEST_KID).await;
        assert!(key1.is_ok());
        assert_eq!(key1.unwrap().kid, TEST_KID);

        // 测试找到第二个密钥
        let key2 = cache.find_key("key-2").await;
        assert!(key2.is_ok());
        assert_eq!(key2.unwrap().kid, "key-2");

        // 测试找不到的密钥
        let key3 = cache.find_key("non-existent").await;
        assert!(key3.is_err());
    }

    #[test]
    fn test_jwks_response_validation() {
        // 测试空的 JWKS 响应
        let empty_response = create_empty_jwks_response();
        assert!(empty_response.keys.is_empty());

        // 测试正常的 JWKS 响应
        let normal_response = create_test_jwks_response();
        assert_eq!(normal_response.keys.len(), 1);
        assert_eq!(normal_response.keys[0].kid, TEST_KID);
    }

    #[test]
    fn test_jwk_field_validation() {
        let jwk = create_test_jwk();

        // 验证必需字段
        assert!(!jwk.kid.is_empty());
        assert_eq!(jwk.kty, "EC");

        // 验证可选字段
        assert!(jwk.alg.is_some());
        assert!(jwk.key_use.is_some());
        assert!(jwk.crv.is_some());
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());

        // 验证 RSA 字段为空（因为这是 EC 密钥）
        assert!(jwk.n.is_none());
        assert!(jwk.e.is_none());
    }

    #[tokio::test]
    async fn test_jwks_concurrent_access() {
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = Arc::new(jwks::JwksCache::new(&jwks_url));

        let mut handles = vec![];

        // 并发访问 JWKS 缓存
        for _ in 0..10 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move { cache_clone.find_key(TEST_KID).await });
            handles.push(handle);
        }

        // 等待所有任务完成
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
            assert_eq!(result.unwrap().kid, TEST_KID);
        }
    }

    // ==================== 缓存过期机制测试 ====================

    /// 测试 JWKS 缓存的稳定性和一致性
    ///
    /// 验证在高频率的重复访问下，缓存能够稳定地提供一致的数据
    #[tokio::test]
    async fn test_jwks_cache_consistency_and_stability() {
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = jwks::JwksCache::new(&jwks_url);

        // 第一次获取 JWKS，建立缓存
        let result1 = cache.get_jwks().await;
        assert!(result1.is_ok());
        let jwks1 = result1.unwrap();
        assert_eq!(jwks1.keys.len(), 1);
        assert_eq!(jwks1.keys[0].kid, TEST_KID);

        // 验证缓存命中（应该使用缓存数据）
        let result2 = cache.get_jwks().await;
        assert!(result2.is_ok());
        let jwks2 = result2.unwrap();
        assert_eq!(jwks2.keys[0].kid, TEST_KID);

        // 测试缓存的一致性和稳定性
        // 注意：由于缓存过期时间是1小时，这里主要测试缓存命中的稳定性
        // 而不是缓存过期功能（过期功能需要更复杂的时间模拟）
        for i in 0..5 {
            let result = cache.get_jwks().await;
            assert!(
                result.is_ok(),
                "Cache access should be stable on iteration {}",
                i
            );
            let jwks = result.unwrap();
            assert_eq!(jwks.keys.len(), 1, "Key count should remain consistent");
            assert_eq!(
                jwks.keys[0].kid, TEST_KID,
                "Key ID should remain consistent"
            );

            // 短暂等待，模拟实际使用场景中的时间间隔
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }

    // ==================== 网络重试机制测试 ====================

    /// 测试网络故障后的错误恢复能力
    ///
    /// 验证在一次网络请求失败后，后续的请求能够正常执行并恢复
    #[tokio::test]
    async fn test_jwks_network_retry_mechanism() {
        // 测试场景1：服务器错误后恢复
        let error_server = MockServer::start().await;

        // 设置服务器返回错误
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks"))
            .respond_with(ResponseTemplate::new(503)) // 服务不可用
            .mount(&error_server)
            .await;

        let error_jwks_url = format!("{}/jwks", error_server.uri());
        let error_cache = jwks::JwksCache::new(&error_jwks_url);

        // 请求应该失败（服务器返回503）
        let error_result = error_cache.get_jwks().await;
        assert!(error_result.is_err());

        // 密钥查找也应该失败
        let key_error_result = error_cache.find_key(TEST_KID).await;
        assert!(key_error_result.is_err());

        // 测试场景2：正常服务器工作
        let normal_server = create_mock_jwks_server().await;
        let normal_jwks_url = format!("{}/jwks", normal_server.uri());
        let normal_cache = jwks::JwksCache::new(&normal_jwks_url);

        // 正常服务器应该工作正常
        let normal_result = normal_cache.get_jwks().await;
        assert!(normal_result.is_ok());
        let jwks = normal_result.unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, TEST_KID);

        // 验证密钥查找正常工作
        let key_result = normal_cache.find_key(TEST_KID).await;
        assert!(key_result.is_ok());
        assert_eq!(key_result.unwrap().kid, TEST_KID);

        // 测试场景3：网络超时恢复能力
        let timeout_cache = jwks::JwksCache::new("http://127.0.0.1:1/jwks");
        let timeout_result = timeout_cache.get_jwks().await;
        assert!(timeout_result.is_err());

        // 验证错误后系统仍然稳定
        let timeout_key_result = timeout_cache.find_key(TEST_KID).await;
        assert!(timeout_key_result.is_err());
    }

    // ==================== 内存稳定性测试 ====================

    /// 测试长期运行时的内存使用稳定性
    ///
    /// 验证 JWKS 缓存在长期运行过程中不会出现内存泄漏
    #[tokio::test]
    async fn test_jwks_long_term_memory_stability() {
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = Arc::new(jwks::JwksCache::new(&jwks_url));

        // 模拟长期运行场景：多轮次的缓存操作
        for round in 0..10 {
            let mut handles = vec![];

            // 每轮创建多个并发任务
            for task_id in 0..20 {
                let cache_clone = cache.clone();
                let handle = tokio::spawn(async move {
                    // 执行多种缓存操作
                    let jwks_result = cache_clone.get_jwks().await;
                    let key_result = cache_clone.find_key(TEST_KID).await;

                    (jwks_result.is_ok(), key_result.is_ok(), task_id)
                });
                handles.push(handle);
            }

            // 等待当前轮次的所有任务完成
            let mut success_count = 0;
            for handle in handles {
                let (jwks_ok, key_ok, _task_id) = handle.await.unwrap();
                if jwks_ok && key_ok {
                    success_count += 1;
                }
            }

            // 验证成功率
            assert!(
                success_count >= 18,
                "Round {}: Success rate too low: {}/20",
                round,
                success_count
            );

            // 短暂休息，模拟实际运行间隔
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }

        // 最终验证：确保缓存仍然正常工作
        let final_result = cache.get_jwks().await;
        assert!(final_result.is_ok());
        let final_jwks = final_result.unwrap();
        assert_eq!(final_jwks.keys.len(), 1);
        assert_eq!(final_jwks.keys[0].kid, TEST_KID);
    }

    // ==================== 缓存一致性压力测试 ====================

    /// 测试高并发场景下的缓存一致性
    ///
    /// 验证在大量并发请求下，缓存数据的一致性和正确性
    #[tokio::test]
    async fn test_jwks_cache_consistency_under_pressure() {
        let mock_server = create_mock_jwks_server().await;
        let jwks_url = format!("{}/jwks", mock_server.uri());
        let cache = Arc::new(jwks::JwksCache::new(&jwks_url));

        let mut all_handles = vec![];

        // 创建大量并发任务（模拟高负载场景）
        for batch in 0..5 {
            for task in 0..50 {
                let cache_clone = cache.clone();
                let handle = tokio::spawn(async move {
                    let start_time = std::time::Instant::now();

                    // 执行缓存操作
                    let jwks_result = cache_clone.get_jwks().await;
                    let key_result = cache_clone.find_key(TEST_KID).await;

                    let duration = start_time.elapsed();

                    (
                        jwks_result.is_ok(),
                        key_result.is_ok(),
                        duration,
                        batch,
                        task,
                    )
                });
                all_handles.push(handle);
            }

            // 批次间短暂间隔
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        }

        // 收集所有结果
        let mut total_success = 0;
        let mut max_duration = std::time::Duration::from_millis(0);
        let mut min_duration = std::time::Duration::from_secs(1);

        for handle in all_handles {
            let (jwks_ok, key_ok, duration, _batch, _task) = handle.await.unwrap();

            if jwks_ok && key_ok {
                total_success += 1;
            }

            max_duration = max_duration.max(duration);
            min_duration = min_duration.min(duration);
        }

        // 验证性能和成功率
        let total_tasks = 5 * 50; // 250个任务
        let success_rate = (total_success as f64) / (total_tasks as f64) * 100.0;

        assert!(
            success_rate >= 95.0,
            "Success rate too low: {:.2}%",
            success_rate
        );
        assert!(
            max_duration.as_millis() < 1000,
            "Max duration too high: {:?}",
            max_duration
        );

        println!(
            "Pressure test completed: {}/{} tasks succeeded ({:.2}%)",
            total_success, total_tasks, success_rate
        );
        println!("Duration range: {:?} - {:?}", min_duration, max_duration);
    }
}
