//! JWT Claims 集成测试
//!
//! 基于 "Claims 作为纯粹信息载体" 的集成验证测试
//!
//! ## 测试重点
//! - **并发安全性**：验证多线程环境下 Claims 访问的线程安全
//! - **序列化性能**：测试大量 Claims 对象的序列化/反序列化效率
//! - **数据完整性**：确保 Claims 数据在并发操作中的一致性
//! - **内存稳定性**：验证长时间运行下的内存使用和稳定性
//!
//! ## 核心验证目标
//! - **信息载体功能**：确保 Claims 专注于数据访问而非业务逻辑
//! - **API 一致性**：验证各种访问方法在并发环境下的行为一致性
//! - **性能基准**：建立 Claims 操作的性能基准和瓶颈识别
//! - **错误处理**：测试异常情况下的优雅降级和错误传播
//!
//! 集成测试确保 Claims 作为信息载体的稳定性和高效性

use super::test_helpers::*;
use crate::claims::Claims;
use serde_json::json;
use std::sync::Arc;
use tokio::task::JoinSet;

// ==================== Claims 核心集成测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试 Claims 在多线程环境下的并发访问安全性
    #[tokio::test]
    async fn test_claims_concurrent_access() {
        let claims = Arc::new(create_test_claims());
        let mut join_set = JoinSet::new();

        // 并发测试多个线程同时访问Claims的各种方法
        for i in 0..20 {
            let claims_clone = claims.clone();

            join_set.spawn(async move {
                let user_id = claims_clone.user_id();
                let email = claims_clone.email();
                let role = claims_clone.role();
                let is_anonymous = claims_clone.is_anonymous();

                // 验证所有访问都返回一致的结果
                (
                    user_id == TEST_USER_ID,
                    email == Some(TEST_EMAIL),
                    role == "authenticated",
                    !is_anonymous,
                    i,
                )
            });
        }

        // 收集所有结果并验证一致性
        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            results.push(result.unwrap());
        }

        assert_eq!(results.len(), 20);
        for (user_id_ok, email_ok, role_ok, not_anonymous, _) in results {
            assert!(user_id_ok, "User ID should be consistent across threads");
            assert!(email_ok, "Email should be consistent across threads");
            assert!(role_ok, "Role should be consistent across threads");
            assert!(
                not_anonymous,
                "Anonymous status should be consistent across threads"
            );
        }
    }

    /// 测试 Claims 元数据的并发访问
    #[tokio::test]
    async fn test_claims_metadata_concurrent_access() {
        let mut claims = create_test_claims();
        claims.user_metadata = Some(json!({
            "counter": 42,
            "data": {
                "nested": "value",
                "array": [1, 2, 3]
            }
        }));

        let claims = Arc::new(claims);
        let mut join_set = JoinSet::new();

        // 并发访问元数据
        for _ in 0..10 {
            let claims_clone = claims.clone();

            join_set.spawn(async move {
                let counter: Option<i32> = claims_clone.get_user_metadata("counter");
                let data: Option<serde_json::Value> = claims_clone.get_user_metadata("data");

                (counter == Some(42), data.is_some())
            });
        }

        // 验证所有并发访问都成功
        let mut success_count = 0;
        while let Some(result) = join_set.join_next().await {
            let (counter_ok, data_ok) = result.unwrap();
            if counter_ok && data_ok {
                success_count += 1;
            }
        }

        assert_eq!(
            success_count, 10,
            "All concurrent metadata accesses should succeed"
        );
    }

    /// 测试 Claims 的序列化和反序列化性能
    #[test]
    fn test_claims_serialization_performance() {
        let mut claims = create_test_claims();

        // 添加适量的元数据
        let mut metadata = serde_json::Map::new();
        for i in 0..100 {
            metadata.insert(
                format!("key_{}", i),
                json!({
                    "id": i,
                    "name": format!("item_{}", i),
                    "data": vec![i; 5]
                }),
            );
        }
        claims.user_metadata = Some(serde_json::Value::Object(metadata));

        // 测试序列化性能
        let start = std::time::Instant::now();
        let serialized = serde_json::to_string(&claims).expect("Should serialize claims");
        let serialize_duration = start.elapsed();

        // 测试反序列化性能
        let start = std::time::Instant::now();
        let deserialized: Claims =
            serde_json::from_str(&serialized).expect("Should deserialize claims");
        let deserialize_duration = start.elapsed();

        // 验证性能（应该在合理时间内完成）
        assert!(
            serialize_duration.as_millis() < 100,
            "Serialization should be fast"
        );
        assert!(
            deserialize_duration.as_millis() < 100,
            "Deserialization should be fast"
        );

        // 验证数据完整性
        assert_eq!(deserialized.sub, claims.sub);
        assert_eq!(deserialized.exp, claims.exp);
        assert_eq!(deserialized.user_metadata, claims.user_metadata);
    }

    /// 测试 Claims 的克隆性能和数据一致性
    #[test]
    fn test_claims_clone_consistency() {
        let original = create_test_claims();

        let start = std::time::Instant::now();
        let mut clones = Vec::new();

        for _ in 0..100 {
            clones.push(original.clone());
        }

        let clone_duration = start.elapsed();

        assert_eq!(clones.len(), 100);
        assert!(
            clone_duration.as_millis() < 10,
            "100 clones should be very fast"
        );

        // 验证所有克隆都是正确的
        for clone in &clones {
            assert_eq!(clone.sub, original.sub);
            assert_eq!(clone.exp, original.exp);
            assert_eq!(clone.email, original.email);
            assert_eq!(clone.role, original.role);
            assert_eq!(clone.user_metadata, original.user_metadata);
        }
    }

    /// 测试 Claims 元数据反序列化失败时的错误处理
    #[test]
    fn test_claims_metadata_deserialization_error() {
        let mut claims = create_test_claims();
        claims.user_metadata = Some(json!({
            "profile": {
                "age": "not_a_number" // 错误类型
            }
        }));

        // 尝试将字符串反序列化为数字，应该返回 None
        let age: Option<i32> = claims.get_user_metadata("profile.age");
        assert!(
            age.is_none(),
            "Should return None for deserialization failure"
        );

        // 尝试将整个 profile 反序列化为强类型 struct
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Profile {
            age: i32,
        }
        let profile: Option<Profile> = claims.get_user_metadata("profile");
        assert!(
            profile.is_none(),
            "Should return None for struct deserialization failure"
        );
    }

    /// 测试 Claims 的内存稳定性 - 长时间运行和大量对象创建
    #[tokio::test]
    async fn test_claims_memory_stability() {
        use std::time::{Duration, Instant};
        use tokio::time::sleep;

        let start_time = Instant::now();
        let test_duration = Duration::from_secs(5); // 5秒的长时间测试
        let mut iteration_count = 0;

        // 模拟长时间运行场景
        while start_time.elapsed() < test_duration {
            let mut claims_batch = Vec::new();

            // 批量创建 Claims 对象
            for i in 0..1000 {
                let mut claims = create_test_claims();
                claims.user_metadata = Some(json!({
                    "batch_id": iteration_count,
                    "item_id": i,
                    "timestamp": start_time.elapsed().as_millis(),
                    "data": vec![i; 10] // 一些数据负载
                }));
                claims_batch.push(claims);
            }

            // 验证所有对象都正确创建
            assert_eq!(claims_batch.len(), 1000);

            // 测试批量访问
            for (i, claims) in claims_batch.iter().enumerate() {
                assert_eq!(claims.user_id(), TEST_USER_ID);
                let batch_id: Option<u64> = claims.get_user_metadata("batch_id");
                assert_eq!(batch_id, Some(iteration_count));
                let item_id: Option<usize> = claims.get_user_metadata("item_id");
                assert_eq!(item_id, Some(i));
            }

            // 显式释放内存
            drop(claims_batch);
            iteration_count += 1;

            // 短暂休眠以模拟实际使用场景
            sleep(Duration::from_millis(10)).await;
        }

        // 验证测试运行了足够的迭代
        assert!(
            iteration_count > 10,
            "Should have completed multiple iterations: {}",
            iteration_count
        );
    }

    /// 测试 Claims 在高并发下的内存使用模式
    #[tokio::test]
    async fn test_claims_concurrent_memory_usage() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let counter = Arc::new(AtomicUsize::new(0));
        let mut join_set = JoinSet::new();

        // 启动多个并发任务，每个任务创建和销毁大量 Claims
        for task_id in 0..10 {
            let counter_clone = counter.clone();

            join_set.spawn(async move {
                let mut local_claims = Vec::new();

                // 每个任务创建 500 个 Claims 对象
                for i in 0..500 {
                    let mut claims = create_test_claims();
                    claims.user_metadata = Some(json!({
                        "task_id": task_id,
                        "local_id": i,
                        "payload": format!("data_{}_{}", task_id, i)
                    }));
                    local_claims.push(claims);
                }

                // 验证所有对象
                for (i, claims) in local_claims.iter().enumerate() {
                    let task_id_meta: Option<usize> = claims.get_user_metadata("task_id");
                    assert_eq!(task_id_meta, Some(task_id));
                    let local_id_meta: Option<usize> = claims.get_user_metadata("local_id");
                    assert_eq!(local_id_meta, Some(i));
                }

                counter_clone.fetch_add(local_claims.len(), Ordering::Relaxed);
                local_claims.len()
            });
        }

        // 等待所有任务完成
        let mut total_processed = 0;
        while let Some(result) = join_set.join_next().await {
            total_processed += result.unwrap();
        }

        // 验证处理了预期数量的对象
        assert_eq!(total_processed, 5000); // 10 tasks * 500 objects
        assert_eq!(counter.load(Ordering::Relaxed), 5000);
    }

    /// 测试 Claims 克隆操作的内存效率
    #[test]
    fn test_claims_clone_memory_efficiency() {
        let original = create_test_claims();
        let start_time = std::time::Instant::now();

        // 创建大量克隆以测试内存使用
        let mut clones = Vec::with_capacity(10000);
        for _ in 0..10000 {
            clones.push(original.clone());
        }

        let clone_duration = start_time.elapsed();

        // 验证性能
        assert!(
            clone_duration.as_millis() < 100,
            "10000 clones should complete quickly: {}ms",
            clone_duration.as_millis()
        );

        // 验证所有克隆的正确性（抽样检查）
        for (i, clone) in clones.iter().enumerate().step_by(1000) {
            assert_eq!(clone.user_id(), original.user_id());
            assert_eq!(clone.email(), original.email());
            assert_eq!(clone.role(), original.role());

            // 每1000个检查一次，确保没有数据损坏
            if i % 1000 == 0 {
                assert_eq!(clone.sub, original.sub);
                assert_eq!(clone.exp, original.exp);
            }
        }

        // 验证总数
        assert_eq!(clones.len(), 10000);
    }

    /// 测试 Claims 序列化在内存压力下的稳定性
    #[test]
    fn test_claims_serialization_under_memory_pressure() {
        let mut large_claims = create_test_claims();

        // 创建大型元数据以增加内存压力
        let mut metadata = serde_json::Map::new();
        for i in 0..1000 {
            metadata.insert(
                format!("large_key_{}", i),
                json!({
                    "id": i,
                    "data": vec![i; 100], // 较大的数据块
                    "nested": {
                        "level1": {
                            "level2": {
                                "value": format!("deep_value_{}", i)
                            }
                        }
                    }
                }),
            );
        }
        large_claims.user_metadata = Some(serde_json::Value::Object(metadata));

        // 多次序列化和反序列化以测试内存稳定性
        for iteration in 0..50 {
            let start = std::time::Instant::now();

            // 序列化
            let serialized =
                serde_json::to_string(&large_claims).expect("Should serialize large claims");

            // 反序列化
            let deserialized: Claims =
                serde_json::from_str(&serialized).expect("Should deserialize large claims");

            let duration = start.elapsed();

            // 验证性能没有显著退化
            assert!(
                duration.as_millis() < 500,
                "Iteration {} took too long: {}ms",
                iteration,
                duration.as_millis()
            );

            // 验证数据完整性
            assert_eq!(deserialized.sub, large_claims.sub);
            assert_eq!(deserialized.user_metadata, large_claims.user_metadata);

            // 每10次迭代验证一次元数据访问
            if iteration % 10 == 0 {
                let test_object: Option<serde_json::Value> =
                    deserialized.get_user_metadata("large_key_500");
                assert!(test_object.is_some());

                // 验证嵌套结构的完整性
                if let Some(obj) = test_object {
                    let nested_value = obj["nested"]["level1"]["level2"]["value"].as_str();
                    assert_eq!(nested_value, Some("deep_value_500"));
                }
            }
        }
    }
}
