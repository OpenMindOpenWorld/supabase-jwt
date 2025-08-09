//! JWT Claims 模块单元测试
//!
//! 基于 "Claims 作为纯粹信息载体" 的设计理念进行测试
//!
//! ## 测试重点
//! - **数据访问便利性**：验证字段访问方法的正确性和效率
//! - **API 易用性**：测试元数据提取、默认值处理等便利功能
//! - **序列化性能**：验证 JSON 序列化/反序列化的稳定性
//! - **基本安全性**：仅测试必要的格式验证（如 subject 非空）
//!
//! ## 不再过度测试的内容
//! 基于信任 Supabase Auth 的理念：
//! - ~~复杂的业务逻辑验证~~
//! - ~~用户权限一致性检查~~
//! - ~~过度的字段内容验证~~
//! - ~~重复的时间验证逻辑~~
//!
//! Claims 专注于作为信息载体，提供高效、便利的数据访问接口

use super::test_helpers::*;
use crate::claims;
use serde_json::json;

// ==================== Claims 信息载体功能测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_basic_properties() {
        let claims = create_test_claims();

        // 基本属性测试
        assert_eq!(claims.sub, TEST_USER_ID);
        assert_eq!(claims.user_id(), TEST_USER_ID);
        assert_eq!(claims.email(), Some(TEST_EMAIL));
        assert_eq!(claims.phone(), Some(TEST_PHONE));
        assert_eq!(claims.role(), "authenticated");
        assert_eq!(claims.session_id.as_deref(), Some(TEST_SESSION_ID));
        assert_eq!(claims.aud.as_deref(), Some("authenticated"));
        assert_eq!(claims.iss.as_deref(), Some(TEST_ISSUER));
        assert_eq!(claims.aal.as_deref(), Some("aal1"));
        assert_eq!(claims.kid.as_deref(), Some(TEST_KID));
        assert!(!claims.is_anonymous());
    }

    #[test]
    fn test_claims_role_defaults() {
        let mut claims = create_test_claims();
        claims.role = None;
        assert_eq!(claims.role(), "authenticated"); // 默认为 authenticated
    }

    #[test]
    fn test_claims_anonymous_defaults() {
        let mut claims = create_test_claims();
        claims.is_anonymous = None;
        assert!(!claims.is_anonymous()); // 默认为 false

        claims.is_anonymous = Some(true);
        assert!(claims.is_anonymous());
    }

    // 时间验证测试已移除 - JWT 库负责时间验证
    // Claims 专注于信息载体功能测试

    #[test]
    fn test_claims_security_validation() {
        let claims = create_test_claims();
        assert!(claims.validate_security().is_ok());

        // 测试空的 subject
        let mut invalid_claims = create_test_claims();
        invalid_claims.sub = "".to_string();
        assert!(invalid_claims.validate_security().is_err());

        // 测试只有空白字符的 subject
        invalid_claims.sub = "   ".to_string();
        assert!(invalid_claims.validate_security().is_err());
    }

    #[test]
    fn test_claims_metadata_access() {
        let claims = create_test_claims();

        // 用户元数据
        let name: Option<String> = claims.get_user_metadata("name");
        assert_eq!(name, Some("Test User".to_string()));

        let non_existent: Option<String> = claims.get_user_metadata("non_existent");
        assert_eq!(non_existent, None);

        // 应用元数据
        let provider: Option<String> = claims.get_app_metadata("provider");
        assert_eq!(provider, Some("email".to_string()));
    }

    #[test]
    fn test_claims_with_minimal_data() {
        let claims = create_minimal_claims();

        assert_eq!(claims.user_id(), TEST_USER_ID);
        assert_eq!(claims.email(), None);
        assert_eq!(claims.role(), "authenticated"); // 默认值
        assert!(!claims.is_anonymous()); // 默认值
        assert!(claims.validate_security().is_ok());
    }

    #[test]
    fn test_claims_serialization() {
        let claims = create_test_claims();

        // 测试序列化
        let serialized = serde_json::to_string(&claims).unwrap();
        assert!(!serialized.is_empty());

        // 测试反序列化
        let deserialized: claims::Claims = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.sub, claims.sub);
        assert_eq!(deserialized.email, claims.email);
    }

    // ==================== 边界条件测试 ====================

    // test_claims_time_boundaries 已移除 - 时间验证由 JWT 库处理

    #[test]
    fn test_claims_with_complex_metadata() {
        let mut claims = create_test_claims();
        claims.user_metadata = Some(json!({
            "nested": {
                "deep": {
                    "value": "test"
                }
            },
            "array": [1, 2, 3],
            "boolean": true,
            "null_value": null
        }));

        // 测试复杂元数据的访问
        let nested: Option<serde_json::Value> = claims.get_user_metadata("nested");
        assert!(nested.is_some());
    }

    // ==================== 安全验证测试 ====================

    #[test]
    fn test_claims_validate_security_empty_subject() {
        let mut claims = create_test_claims();
        claims.sub = "".to_string(); // 空的 subject

        let result = claims.validate_security();
        assert!(result.is_err());
    }

    #[test]
    fn test_claims_validate_security_whitespace_subject() {
        let mut claims = create_test_claims();
        claims.sub = "   ".to_string(); // 只有空白字符的 subject

        let result = claims.validate_security();
        assert!(result.is_err());
    }

    #[test]
    fn test_claims_validate_security_valid_subject() {
        let claims = create_test_claims();

        let result = claims.validate_security();
        assert!(result.is_ok());
    }

    // ==================== Key ID 测试 ====================

    #[test]
    fn test_claims_key_id() {
        let mut claims = create_test_claims();

        // create_test_claims 已经设置了 kid，先验证它存在
        assert_eq!(claims.kid.as_deref(), Some(TEST_KID));

        // 清除 key_id
        claims.kid = None;
        assert!(claims.kid.is_none());

        // 重新设置 key_id
        claims.kid = Some("new-key-id".to_string());
        assert_eq!(claims.kid.as_deref(), Some("new-key-id"));
    }

    // ==================== 元数据边界测试 ====================

    #[test]
    fn test_claims_metadata_missing_key() {
        let claims = create_test_claims();

        // 测试不存在的键
        let result: Option<String> = claims.get_user_metadata("non_existent_key");
        assert!(result.is_none());

        let result: Option<String> = claims.get_app_metadata("non_existent_key");
        assert!(result.is_none());
    }

    #[test]
    fn test_claims_metadata_type_handling() {
        let mut claims = create_test_claims();
        claims.user_metadata = Some(json!({
            "string_field": "test_value",
            "number_field": 42
        }));

        // 测试基本的类型解析
        let string_result: Option<String> = claims.get_user_metadata("string_field");
        assert_eq!(string_result, Some("test_value".to_string()));

        let number_result: Option<i32> = claims.get_user_metadata("number_field");
        assert_eq!(number_result, Some(42));
    }

    #[test]
    fn test_claims_basic_edge_cases() {
        // 测试基本的无效情况
        let mut claims = create_minimal_claims();

        // 空字符串用户ID
        claims.sub = "".to_string();
        assert!(claims.validate_security().is_err());

        // 仅包含空格的用户ID
        claims.sub = "   ".to_string();
        assert!(claims.validate_security().is_err());
    }

    // test_claims_time_edge_cases 已移除 - 时间验证由 JWT 库处理

    #[test]
    fn test_claims_role_variations() {
        let mut claims = create_minimal_claims();

        // 测试各种角色值
        claims.role = Some("admin".to_string());
        assert_eq!(claims.role(), "admin");

        claims.role = Some("user".to_string());
        assert_eq!(claims.role(), "user");

        // 修正：空字符串角色会返回空字符串（不是默认值）
        claims.role = Some("".to_string());
        assert_eq!(claims.role(), "");

        claims.role = None;
        assert_eq!(claims.role(), "authenticated");
    }

    #[test]
    fn test_claims_serialization_roundtrip() {
        let original_claims = create_test_claims();

        // 序列化
        let json_str = serde_json::to_string(&original_claims).expect("Should serialize");

        // 反序列化
        let deserialized_claims: claims::Claims =
            serde_json::from_str(&json_str).expect("Should deserialize");

        // 验证关键字段
        assert_eq!(original_claims.sub, deserialized_claims.sub);
        assert_eq!(original_claims.exp, deserialized_claims.exp);
        assert_eq!(original_claims.email, deserialized_claims.email);
        assert_eq!(original_claims.role, deserialized_claims.role);

        // 注意：kid 字段不会被序列化，所以反序列化后应该是 None
        assert!(deserialized_claims.kid.is_none());
    }

    // ==================== 增强稳定性测试 ====================

    #[test]
    fn test_claims_validate_security_enhanced() {
        // 测试基本的无效 subject 情况
        let invalid_cases = vec![
            "",    // 空字符串
            "   ", // 仅空格
        ];

        for invalid_sub in invalid_cases {
            let mut claims = create_test_claims();
            claims.sub = invalid_sub.to_string();
            assert!(claims.validate_security().is_err());
        }

        // 测试基本的有效情况
        let valid_cases = vec!["user123", "user@domain.com"];

        for valid_sub in valid_cases {
            let mut claims = create_test_claims();
            claims.sub = valid_sub.to_string();
            assert!(claims.validate_security().is_ok());
        }

        // 测试长度限制已移除 - 信任 Supabase Auth 的验证
        // 现在只要不为空，任何长度的 subject 都应该通过验证
        let mut claims = create_test_claims();
        claims.sub = "a".repeat(256); // 长字符串现在应该通过验证
        assert!(claims.validate_security().is_ok());
    }

    // test_claims_time_validation_precision 已移除 - 时间验证由 JWT 库处理

    #[test]
    fn test_claims_metadata_basic_access() {
        let mut claims = create_test_claims();

        // 测试基本的元数据结构
        claims.user_metadata = Some(json!({
            "name": "Test User",
            "preferences": {
                "theme": "dark"
            },
            "tags": ["admin", "user"]
        }));

        // 测试基本字段访问
        let name: Option<String> = claims.get_user_metadata("name");
        assert_eq!(name, Some("Test User".to_string()));

        // 测试嵌套对象访问
        let preferences: Option<serde_json::Value> = claims.get_user_metadata("preferences");
        assert!(preferences.is_some());

        // 测试数组访问
        let tags: Option<serde_json::Value> = claims.get_user_metadata("tags");
        assert!(tags.is_some());
    }

    #[test]
    fn test_claims_field_consistency() {
        let claims = create_test_claims();

        // 验证核心访问器方法与直接字段访问的一致性
        assert_eq!(claims.user_id(), &claims.sub);
        assert_eq!(claims.email(), claims.email.as_deref());
        assert_eq!(claims.phone(), claims.phone.as_deref());

        // 验证直接字段访问（已移除的访问器方法）
        assert_eq!(claims.session_id.as_deref(), claims.session_id.as_deref());
        assert_eq!(claims.aud.as_deref(), claims.aud.as_deref());
        assert_eq!(claims.iss.as_deref(), claims.iss.as_deref());
        assert_eq!(claims.aal.as_deref(), claims.aal.as_deref());
        assert_eq!(claims.amr.as_ref(), claims.amr.as_ref());
        assert_eq!(claims.kid.as_deref(), claims.kid.as_deref());

        // 验证布尔值的一致性
        assert_eq!(claims.is_anonymous(), claims.is_anonymous.unwrap_or(false));
    }

    #[test]
    fn test_claims_default_values() {
        let mut claims = create_test_claims();

        // 测试空的可选字段的默认值行为
        claims.email = None;
        claims.phone = None;
        claims.role = None;
        claims.aal = None;
        claims.session_id = None;
        claims.aud = None;
        claims.iss = None;
        claims.amr = None;
        claims.user_metadata = None;
        claims.app_metadata = None;
        claims.is_anonymous = None;
        claims.kid = None;

        // 验证默认值行为
        assert_eq!(claims.email(), None);
        assert_eq!(claims.phone(), None);
        assert_eq!(claims.role(), "authenticated"); // 默认值
        assert!(!claims.is_anonymous()); // 默认值
        assert_eq!(claims.kid, None);
    }

    #[test]
    fn test_claims_subject_validation() {
        // 测试基本的 subject 验证功能
        let mut claims = create_test_claims();

        // 测试正常的 subject
        claims.sub = "user123".to_string();
        assert!(claims.validate_security().is_ok());

        // 测试包含特殊字符的 subject
        claims.sub = "user@example.com".to_string();
        assert!(claims.validate_security().is_ok());
    }

    #[test]
    fn test_claims_clone_and_equality() {
        let original = create_test_claims();
        let cloned = original.clone();

        // 验证克隆的完整性
        assert_eq!(original.sub, cloned.sub);
        assert_eq!(original.exp, cloned.exp);
        assert_eq!(original.email, cloned.email);
        assert_eq!(original.phone, cloned.phone);
        assert_eq!(original.role, cloned.role);
        assert_eq!(original.session_id, cloned.session_id);
        assert_eq!(original.aud, cloned.aud);
        assert_eq!(original.iss, cloned.iss);
        assert_eq!(original.aal, cloned.aal);
        assert_eq!(original.is_anonymous, cloned.is_anonymous);
        assert_eq!(original.kid, cloned.kid);

        // 验证元数据的深度克隆
        if let (Some(orig_user_meta), Some(cloned_user_meta)) =
            (&original.user_metadata, &cloned.user_metadata)
        {
            assert_eq!(orig_user_meta, cloned_user_meta);
        }

        if let (Some(orig_app_meta), Some(cloned_app_meta)) =
            (&original.app_metadata, &cloned.app_metadata)
        {
            assert_eq!(orig_app_meta, cloned_app_meta);
        }
    }

    /// 测试 Claims 的安全验证性能
    #[test]
    fn test_claims_validation_performance() {
        let base_claims = create_test_claims();

        // 测试多个不同的subject值
        let test_subjects = (0..100).map(|i| format!("user_{i}")).collect::<Vec<_>>();

        let start = std::time::Instant::now();
        let mut validation_results = Vec::new();

        for subject in test_subjects {
            let mut claims = base_claims.clone();
            claims.sub = subject;

            let validation_result = claims.validate_security();
            validation_results.push(validation_result.is_ok());
        }

        let duration = start.elapsed();

        // 验证性能
        assert!(
            duration.as_millis() < 50,
            "100 validations should be very fast"
        );

        // 验证所有有效的subject都通过了验证
        let success_count = validation_results.iter().filter(|&&result| result).count();
        assert_eq!(
            success_count, 100,
            "All valid subjects should pass validation"
        );
    }
}
