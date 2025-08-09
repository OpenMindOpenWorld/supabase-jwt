//! # JWT 认证模块测试套件
//!
//! 本模块专为 Supabase Auth 设计，提供一个高性能、高稳定性的 JWT 验证功能。
//! 设计核心在于信任上游（Supabase Auth），并专注于解析过程的稳定性与性能。
//!
//! ## 设计与测试策略
//!
//! - **信任上游**：完全信任 Supabase Auth 生成的 Token，不重复验证其内容。
//! - **快速失败**：对任何格式异常的 Token 立即拒绝，保证系统安全。
//! - **专注解析**：核心任务是高效、稳定地完成 Base64 解码和 JSON 反序列化。
//! - **性能优化**：通过并发解析、智能缓存等机制，确保低延迟、高吞吐。
//! - **线程安全**：保障 JWKS 缓存在多线程环境下的数据一致性和访问安全。
//! - **API 易用性**：提供简洁、高效的 Claims 访问接口。
//!
//! ## 不在测试范围内的内容
//!
//! - 复杂的 Claims 业务逻辑验证。
//! - 用户权限和状态的同步检查。
//! - 针对上游服务的安全攻击模拟。
//! - JWT 标准时间字段的重复验证（依赖 `jsonwebtoken` 库）。
//!
//! ## 模块结构
//!
//! - `test_helpers`: 提供共享的测试辅助函数与常量。
//! - `claims_tests`: 验证 Claims 作为数据载体的功能和 API。
//! - `claims_integration_tests`: 测试 Claims 的并发安全与序列化性能。
//! - `jwks_tests`: 检验 JWKS 的智能缓存与并发安全机制。
//! - `jwks_cache_expiration_tests`: 测试 JWKS 缓存的24小时有效性与7天优雅降级策略。
//! - `parser_tests`: 评估 JWT 解析的稳定性与性能。
//! - `integration_tests`: 进行端到端的流程验证与组件协同测试。

// 共享测试辅助模块
pub mod test_helpers;

// 测试模块声明
pub mod claims_integration_tests;
pub mod claims_tests;
pub mod integration_tests;
pub mod jwks_cache_expiration_tests;
pub mod jwks_tests;
pub mod parser_tests;
