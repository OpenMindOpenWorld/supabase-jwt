//! JWKS 缓存过期机制测试模块
//!
//! 基于 JWKS 公钥稳定性特点的缓存生命周期测试
//!
//! ## JWKS 缓存特点
//! JWKS 公钥在生产环境中通常具有以下特点：
//! - **变动频率低**：公钥轮换周期通常以月或年为单位
//! - **稳定性高**：一旦发布，公钥在有效期内保持不变
//! - **容错要求高**：网络故障时需要降级到缓存保证服务可用性
//!
//! ## 测试重点
//! - **24小时有效缓存**：验证缓存在有效期内的正常命中和使用
//! - **7天优雅降级**：测试过期缓存的降级使用和自动刷新机制
//! - **网络故障容错**：验证网络异常时的缓存降级和恢复能力
//! - **并发访问安全**：确保多线程环境下缓存操作的线程安全性
//! - **缓存刷新机制**：测试适合公钥特点的后台缓存更新策略
//!
//! ## 核心机制验证
//! - **稳定性优先策略**：长期有效缓存，降级容错，避免频繁刷新
//! - **容错降级机制**：网络故障时使用过期缓存保证服务连续性
//! - **线程安全保障**：并发访问下的数据一致性和操作安全性
//! - **简化刷新逻辑**：适应公钥低变动频率的刷新策略
//!
//! 确保 JWKS 缓存在公钥稳定场景下的可靠性和高可用性

use super::test_helpers::*;
use crate::jwks;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};

// 测试用的缓存时间常量（缩短以便测试）
const TEST_CACHE_DURATION: u64 = 2; // 2秒有效缓存（模拟24小时）
const TEST_CACHE_MAX_AGE: u64 = 5; // 5秒最大缓存（模拟7天）

/// 创建一个可以注入自定义时间的测试 JWKS 缓存
/// 专为 JWKS 公钥稳定性场景设计，支持长期缓存和网络容错
struct TestableJwksCache {
    cache: Arc<RwLock<Option<jwks::JwksResponse>>>,
    expires_at: Arc<RwLock<Option<u64>>>,
    cached_at: Arc<RwLock<Option<u64>>>,
    current_time: Arc<RwLock<u64>>, // 用于模拟当前时间

    // 基本统计
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    refresh_attempts: Arc<AtomicU64>,
    refresh_successes: Arc<AtomicU64>,

    // 网络容错
    network_available: Arc<AtomicBool>,

    // 刷新控制
    auto_refresh_enabled: Arc<AtomicBool>,
    refresh_mutex: Arc<Mutex<()>>,
}

impl TestableJwksCache {
    /// 创建新的可测试 JWKS 缓存
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            cache: Arc::new(RwLock::new(None)),
            expires_at: Arc::new(RwLock::new(None)),
            cached_at: Arc::new(RwLock::new(None)),
            current_time: Arc::new(RwLock::new(now)),

            // 初始化性能统计
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            refresh_attempts: Arc::new(AtomicU64::new(0)),
            refresh_successes: Arc::new(AtomicU64::new(0)),

            // 初始化网络容错（默认网络可用）
            network_available: Arc::new(AtomicBool::new(true)),

            // 初始化刷新控制（默认启用）
            auto_refresh_enabled: Arc::new(AtomicBool::new(true)),
            refresh_mutex: Arc::new(Mutex::new(())),
        }
    }

    /// 前进模拟时间
    pub async fn advance_time(&self, seconds: u64) {
        let mut time = self.current_time.write().await;
        *time += seconds;
    }

    /// 获取当前模拟时间
    pub async fn get_current_time(&self) -> u64 {
        *self.current_time.read().await
    }

    /// 设置缓存数据和时间戳
    pub async fn set_cache(&self, jwks: jwks::JwksResponse) {
        let now = self.get_current_time().await;
        *self.cache.write().await = Some(jwks);
        *self.expires_at.write().await = Some(now + TEST_CACHE_DURATION);
        *self.cached_at.write().await = Some(now);
    }

    /// 获取有效的缓存数据（模拟24小时内）
    pub async fn get_cached_jwks(&self) -> Option<jwks::JwksResponse> {
        let now = self.get_current_time().await;
        let expires_at = *self.expires_at.read().await;

        if let Some(expires) = expires_at {
            if now < expires {
                return self.cache.read().await.clone();
            }
        }
        None
    }

    /// 获取过期缓存作为降级方案（模拟7天内）
    pub async fn get_stale_cache(&self) -> Option<jwks::JwksResponse> {
        let now = self.get_current_time().await;
        let cached_at = *self.cached_at.read().await;

        if let Some(cache_time) = cached_at {
            if now - cache_time <= TEST_CACHE_MAX_AGE {
                return self.cache.read().await.clone();
            }
        }
        None
    }

    // ==================== 网络容错方法 ====================

    /// 设置网络可用性
    pub fn set_network_available(&self, available: bool) {
        self.network_available.store(available, Ordering::Relaxed);
    }

    /// 模拟网络请求
    pub async fn simulate_network_request(&self) -> Result<jwks::JwksResponse, String> {
        // 检查网络可用性
        if !self.network_available.load(Ordering::Relaxed) {
            return Err("Network unavailable".to_string());
        }

        // 返回模拟的 JWKS 响应
        Ok(create_test_jwks_response())
    }

    // ==================== 缓存刷新方法 ====================

    /// 启用/禁用缓存刷新
    pub fn set_auto_refresh_enabled(&self, enabled: bool) {
        self.auto_refresh_enabled.store(enabled, Ordering::Relaxed);
    }

    /// 带容错降级的缓存获取（模拟真实的 get_jwks_with_fallback）
    pub async fn get_jwks_with_auto_refresh(&self) -> Result<jwks::JwksResponse, String> {
        // 1. 尝试使用有效缓存
        if let Some(cached) = self.get_cached_jwks().await {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(cached);
        }

        self.cache_misses.fetch_add(1, Ordering::Relaxed);

        // 2. 缓存过期，尝试自动刷新
        if self.auto_refresh_enabled.load(Ordering::Relaxed) {
            let _lock = self.refresh_mutex.lock().await;
            self.refresh_attempts.fetch_add(1, Ordering::Relaxed);

            match self.simulate_network_request().await {
                Ok(jwks) => {
                    self.set_cache(jwks.clone()).await;
                    self.refresh_successes.fetch_add(1, Ordering::Relaxed);
                    return Ok(jwks);
                }
                Err(_) => {
                    // 网络失败，尝试使用过期缓存
                    if let Some(stale) = self.get_stale_cache().await {
                        return Ok(stale);
                    }
                }
            }
        }

        Err("No cache available and refresh failed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试有效缓存期内（模拟24小时内）的缓存命中
    #[tokio::test]
    async fn test_valid_cache_hit() {
        // 创建测试缓存
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;
        let initial_time = cache.get_current_time().await;

        // 验证缓存命中
        let cached_jwks = cache.get_cached_jwks().await;
        assert!(cached_jwks.is_some());
        assert_eq!(cached_jwks.unwrap().keys[0].kid, TEST_KID);

        // 前进时间但仍在有效期内（1秒，模拟12小时）
        cache.advance_time(1).await;
        assert!(cache.get_current_time().await < initial_time + TEST_CACHE_DURATION);

        // 验证仍然命中有效缓存
        let cached_jwks = cache.get_cached_jwks().await;
        assert!(cached_jwks.is_some());
        assert_eq!(cached_jwks.unwrap().keys[0].kid, TEST_KID);
    }

    /// 测试缓存过期但在最大缓存期内（模拟24小时后但7天内）的降级缓存
    #[tokio::test]
    async fn test_stale_cache_fallback() {
        // 创建测试缓存
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;
        let initial_time = cache.get_current_time().await;

        // 前进时间超过有效期但在最大缓存期内（3秒，模拟3天）
        cache.advance_time(TEST_CACHE_DURATION + 1).await;
        assert!(cache.get_current_time().await > initial_time + TEST_CACHE_DURATION);
        assert!(cache.get_current_time().await < initial_time + TEST_CACHE_MAX_AGE);

        // 验证有效缓存已过期
        let cached_jwks = cache.get_cached_jwks().await;
        assert!(cached_jwks.is_none());

        // 验证可以使用过期缓存作为降级方案
        let stale_jwks = cache.get_stale_cache().await;
        assert!(stale_jwks.is_some());
        assert_eq!(stale_jwks.unwrap().keys[0].kid, TEST_KID);
    }

    /// 测试超过最大缓存期（模拟7天后）的情况
    #[tokio::test]
    async fn test_cache_max_age_expiration() {
        // 创建测试缓存
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;
        let initial_time = cache.get_current_time().await;

        // 前进时间超过最大缓存期（6秒，模拟8天）
        cache.advance_time(TEST_CACHE_MAX_AGE + 1).await;
        assert!(cache.get_current_time().await > initial_time + TEST_CACHE_MAX_AGE);

        // 验证有效缓存已过期
        let cached_jwks = cache.get_cached_jwks().await;
        assert!(cached_jwks.is_none());

        // 验证过期缓存也不可用
        let stale_jwks = cache.get_stale_cache().await;
        assert!(stale_jwks.is_none());
    }

    /// 测试缓存刷新后的新有效期
    #[tokio::test]
    async fn test_cache_refresh_extends_validity() {
        // 创建测试缓存
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;
        let _initial_time = cache.get_current_time().await;

        // 前进时间接近有效期但未过期（1秒，模拟20小时）
        cache.advance_time(1).await;

        // 刷新缓存
        let updated_jwks = create_test_jwks_response(); // 可以是相同数据，模拟刷新
        cache.set_cache(updated_jwks).await;
        let refresh_time = cache.get_current_time().await;

        // 前进时间但仍在新的有效期内（1秒，模拟再过12小时）
        cache.advance_time(1).await;
        assert!(cache.get_current_time().await < refresh_time + TEST_CACHE_DURATION);

        // 验证仍然命中有效缓存
        let cached_jwks = cache.get_cached_jwks().await;
        assert!(cached_jwks.is_some());
        assert_eq!(cached_jwks.unwrap().keys[0].kid, TEST_KID);

        // 前进时间超过新的有效期（再过2秒，总共已过4秒）
        cache.advance_time(2).await;
        assert!(cache.get_current_time().await > refresh_time + TEST_CACHE_DURATION);

        // 验证有效缓存已过期
        let cached_jwks = cache.get_cached_jwks().await;
        assert!(cached_jwks.is_none());

        // 但仍在最大缓存期内
        let stale_jwks = cache.get_stale_cache().await;
        assert!(stale_jwks.is_some());
    }

    /// 测试缓存的初始状态是否为空
    #[tokio::test]
    async fn test_initial_state_is_empty() {
        // 创建测试缓存
        let cache = TestableJwksCache::new();

        // 验证初始状态下，获取有效缓存和过期缓存都应返回 None
        let valid_jwks = cache.get_cached_jwks().await;
        assert!(valid_jwks.is_none(), "Initial valid cache should be empty");

        let stale_jwks = cache.get_stale_cache().await;
        assert!(stale_jwks.is_none(), "Initial stale cache should be empty");
    }

    /// 测试并发访问下的线程安全性
    #[tokio::test]
    async fn test_concurrent_access_is_safe() {
        // 创建一个在多个任务间共享的缓存实例
        let cache = Arc::new(TestableJwksCache::new());
        let test_jwks = create_test_jwks_response();

        // 初始设置缓存
        cache.set_cache(test_jwks).await;
        let initial_time = cache.get_current_time().await;

        let mut tasks = vec![];

        // 创建多个并发任务，只进行读取操作以测试线程安全性
        for i in 0..10 {
            let cache_clone = Arc::clone(&cache);
            tasks.push(tokio::spawn(async move {
                // 模拟并发读取
                let jwks = cache_clone.get_cached_jwks().await;
                assert!(jwks.is_some(), "Task {} should read valid cache", i);
                assert_eq!(jwks.unwrap().keys[0].kid, TEST_KID);

                // 模拟并发的过期缓存读取
                let stale_jwks = cache_clone.get_stale_cache().await;
                assert!(stale_jwks.is_some(), "Task {} should read stale cache", i);
                assert_eq!(stale_jwks.unwrap().keys[0].kid, TEST_KID);
            }));
        }

        // 等待所有任务完成
        for task in tasks {
            task.await.unwrap();
        }

        // 验证在并发访问后，缓存状态依然正确
        let final_time = cache.get_current_time().await;
        assert_eq!(
            final_time, initial_time,
            "Time should not advance during read-only operations"
        );

        // 验证缓存仍然有效
        let valid_jwks = cache.get_cached_jwks().await;
        assert!(
            valid_jwks.is_some(),
            "Cache should still be valid after concurrent reads"
        );

        // 现在测试并发写入的情况
        // 现在测试并发写入的情况
        let mut write_tasks = vec![];
        let new_jwks = create_test_jwks_response();

        // 记录开始并发写入前的时间
        let before_write_time = cache.get_current_time().await;

        for _ in 0..5 {
            // 循环5次，模拟5个并发写操作
            let cache_clone = Arc::clone(&cache);
            let jwks_clone = new_jwks.clone();
            write_tasks.push(tokio::spawn(async move {
                // 模拟多个线程同时尝试更新缓存
                // 在这个模型里，set_cache会使用它被调用时的 "now"
                cache_clone.set_cache(jwks_clone).await;
            }));
        }

        // 等待所有写入任务完成
        for task in write_tasks {
            task.await.unwrap();
        }

        // 写入操作完成后，时间不应改变，因为 set_cache 内部不推进时间
        let after_write_time = cache.get_current_time().await;
        assert_eq!(
            before_write_time, after_write_time,
            "Time should not advance during concurrent set_cache calls"
        );

        // 现在，手动将时间快进到所有可能的缓存都已过期的时刻
        cache.advance_time(TEST_CACHE_MAX_AGE + 1).await;

        // 验证在时间快进后，所有缓存都已过期
        let final_time = cache.get_current_time().await;
        assert!(final_time > after_write_time + TEST_CACHE_MAX_AGE);

        // 由于时间已经快进，远超过TEST_CACHE_MAX_AGE(5秒)，所有缓存都应该过期
        let expired_valid_jwks = cache.get_cached_jwks().await;
        assert!(
            expired_valid_jwks.is_none(),
            "Cache should be expired after advancing time past MAX_AGE"
        );

        let expired_stale_jwks = cache.get_stale_cache().await;
        assert!(
            expired_stale_jwks.is_none(),
            "Stale cache should also be expired after advancing time past MAX_AGE"
        );
    }

    // ==================== 网络容错机制测试 ====================

    /// 测试网络可用时的基本刷新功能
    #[tokio::test]
    async fn test_basic_refresh_on_network_available() {
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;

        // 前进时间使缓存过期
        cache.advance_time(TEST_CACHE_DURATION + 1).await;

        // 确保网络可用
        cache.set_network_available(true);
        cache.set_auto_refresh_enabled(true);

        // 尝试获取 JWKS，应该能够刷新
        let result = cache.get_jwks_with_auto_refresh().await;
        assert!(
            result.is_ok(),
            "Should refresh successfully when network is available"
        );

        // 验证基本刷新统计
        assert_eq!(cache.refresh_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(cache.refresh_successes.load(Ordering::Relaxed), 1);
    }

    /// 测试网络不可用时的降级缓存使用
    #[tokio::test]
    async fn test_fallback_to_stale_cache_on_network_failure() {
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;

        // 前进时间使缓存过期但仍在最大缓存期内
        cache.advance_time(TEST_CACHE_DURATION + 1).await;

        // 模拟网络不可用
        cache.set_network_available(false);
        cache.set_auto_refresh_enabled(true);

        // 尝试获取 JWKS，应该使用过期缓存作为降级方案
        let result = cache.get_jwks_with_auto_refresh().await;
        assert!(
            result.is_ok(),
            "Should fallback to stale cache when network fails"
        );

        // 验证统计数据
        assert_eq!(cache.refresh_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(cache.refresh_successes.load(Ordering::Relaxed), 0);
    }

    /// 测试禁用刷新时的降级行为
    #[tokio::test]
    async fn test_disabled_refresh_fallback() {
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;

        // 前进时间使缓存过期但仍在降级期内
        cache.advance_time(TEST_CACHE_DURATION + 1).await;

        // 禁用自动刷新
        cache.set_auto_refresh_enabled(false);
        cache.set_network_available(true);

        // 尝试获取 JWKS，应该失败（因为禁用了刷新且没有有效缓存）
        let result = cache.get_jwks_with_auto_refresh().await;
        assert!(
            result.is_err(),
            "Should fail when refresh is disabled and cache is expired"
        );

        // 验证没有刷新尝试
        assert_eq!(cache.refresh_attempts.load(Ordering::Relaxed), 0);
    }

    // ==================== 网络容错处理测试 ====================

    /// 测试网络故障时的降级机制
    #[tokio::test]
    async fn test_network_failure_fallback() {
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;
        cache.advance_time(TEST_CACHE_DURATION + 1).await;

        // 模拟网络故障
        cache.set_network_available(false);
        let result = cache.get_jwks_with_auto_refresh().await;
        assert!(
            result.is_ok(),
            "Should use stale cache during network failure"
        );

        // 验证使用的是降级缓存
        assert_eq!(cache.refresh_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(cache.refresh_successes.load(Ordering::Relaxed), 0);
    }

    /// 测试网络恢复后的正常工作
    #[tokio::test]
    async fn test_network_recovery() {
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;
        cache.advance_time(TEST_CACHE_DURATION + 1).await;

        // 先模拟网络故障
        cache.set_network_available(false);
        let _ = cache.get_jwks_with_auto_refresh().await;

        // 网络恢复
        cache.set_network_available(true);
        let result = cache.get_jwks_with_auto_refresh().await;
        assert!(
            result.is_ok(),
            "Should work normally after network recovery"
        );
    }

    // ==================== 边界条件测试 ====================

    /// 测试缓存过期边界条件
    #[tokio::test]
    async fn test_cache_expiration_boundaries() {
        let cache = TestableJwksCache::new();
        let test_jwks = create_test_jwks_response();

        // 设置初始缓存
        cache.set_cache(test_jwks.clone()).await;
        let initial_time = cache.get_current_time().await;

        // 测试缓存即将过期的时刻（过期前1秒）
        cache.advance_time(TEST_CACHE_DURATION - 1).await;
        let cached = cache.get_cached_jwks().await;
        assert!(
            cached.is_some(),
            "Cache should still be valid before expiration"
        );

        // 测试缓存刚好过期的时刻
        cache.advance_time(1).await;
        assert_eq!(
            cache.get_current_time().await,
            initial_time + TEST_CACHE_DURATION
        );
        let cached = cache.get_cached_jwks().await;
        assert!(
            cached.is_none(),
            "Cache should be expired at expiration time"
        );

        // 测试过期缓存仍可用的边界
        let stale = cache.get_stale_cache().await;
        assert!(
            stale.is_some(),
            "Stale cache should be available within max age"
        );

        // 测试超过最大缓存期的边界
        cache
            .advance_time(TEST_CACHE_MAX_AGE - TEST_CACHE_DURATION + 1)
            .await;
        let stale = cache.get_stale_cache().await;
        assert!(
            stale.is_none(),
            "Stale cache should not be available beyond max age"
        );
    }
}
