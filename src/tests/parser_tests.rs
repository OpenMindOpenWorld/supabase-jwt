//! Supabase Auth JWT 解析器稳定性测试
//!
//! 基于 "信任 Supabase Auth，快速失败非正常 token" 的设计理念
//!
//! ## 测试重点
//! - **解析器稳定性**：确保对各种输入格式的鲁棒性处理
//! - **快速失败机制**：验证非正常 token 的快速识别和拒绝
//! - **格式验证效率**：测试 Base64 解码、JSON 解析的性能和准确性
//! - **算法支持专一性**：仅支持 ES256 (ECC P-256) 算法的严格验证
//!
//! ## 核心设计理念
//! - **信任 Supabase Auth**：假设正常 token 来自可信源
//! - **专用解析器**：专门为 Supabase Auth JWT 优化
//! - **快速拒绝**：对格式错误、算法不匹配等情况立即失败
//! - **性能优先**：避免过度验证，专注解析效率
//!
//! 测试避免依赖具体的公私钥对，使用模拟数据确保测试独立性

use super::test_helpers::*;
use crate::parser;
use crate::AuthError;
use base64::Engine as _;
use jsonwebtoken::Algorithm;

// ==================== Supabase Auth JWT Parser 模块测试 ====================
// 注意：此解析器专门为 Supabase Auth 设计，仅支持 ES256 (ECC P-256) 算法

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_header_valid() {
        let token = create_mock_jwt_token();

        let result = parser::JwtParser::decode_header(&token);
        assert!(
            result.is_ok(),
            "Should successfully decode valid JWT header"
        );

        let header = result.expect("Should decode valid JWT header");
        assert_eq!(header.alg, "ES256", "Algorithm should be ES256");
        assert_eq!(
            header.kid,
            Some(TEST_KID.to_string()),
            "Key ID should match test key ID"
        );
        assert_eq!(
            header.typ,
            Some("JWT".to_string()),
            "Token type should be JWT"
        );
    }

    #[test]
    fn test_decode_header_invalid_inputs() {
        // 空 token
        assert!(
            parser::JwtParser::decode_header("").is_err(),
            "Empty token should be rejected"
        );
        assert!(
            parser::JwtParser::decode_header("   ").is_err(),
            "Whitespace-only token should be rejected"
        );
        assert!(
            parser::JwtParser::decode_header("\t\n\r").is_err(),
            "Token with only whitespace characters should be rejected"
        );

        // 格式错误
        assert!(
            parser::JwtParser::decode_header("invalid.token").is_err(),
            "Two-part token should be rejected"
        );
        assert!(
            parser::JwtParser::decode_header("too.many.parts.here").is_err(),
            "Four-part token should be rejected"
        );
        assert!(
            parser::JwtParser::decode_header("single_part").is_err(),
            "Single-part token should be rejected"
        );
        assert!(
            parser::JwtParser::decode_header("no_dots_at_all").is_err(),
            "Token without dots should be rejected"
        );

        // 空的部分
        assert!(
            parser::JwtParser::decode_header(".payload.signature").is_err(),
            "Empty header part should be rejected"
        );
        assert!(
            parser::JwtParser::decode_header("header..signature").is_err(),
            "Empty payload part should be rejected"
        );
        assert!(
            parser::JwtParser::decode_header("header.payload.").is_err(),
            "Empty signature part should be rejected"
        );
        assert!(
            parser::JwtParser::decode_header("...").is_err(),
            "All empty parts should be rejected"
        );

        // 过长的 token
        let long_token = "a".repeat(10000);
        assert!(
            parser::JwtParser::decode_header(&long_token).is_err(),
            "Excessively long token should be rejected"
        );

        // 测试边界长度 - 创建有效格式但过长的 token
        let long_header = "a".repeat(2700); // 约 2700 字符的 header 部分
        let long_payload = "b".repeat(2700); // 约 2700 字符的 payload 部分
        let long_signature = "c".repeat(2700); // 约 2700 字符的 signature 部分
        let boundary_token = format!("{long_header}.{long_payload}.{long_signature}"); // 总长度约 8100+ 字符
        assert!(
            parser::JwtParser::decode_header(&boundary_token).is_err(),
            "Token exceeding length limit should be rejected"
        );

        // 测试刚好在长度限制内的有效格式 token
        let valid_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"ES256","kid":"test"}"#);
        let valid_payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
        let valid_signature = "signature";
        let valid_token = format!("{valid_header}.{valid_payload}.{valid_signature}");
        // 这个 token 应该能成功解析 header（即使签名无效）
        assert!(
            parser::JwtParser::decode_header(&valid_token).is_ok(),
            "Valid format token should parse header successfully"
        );
    }

    #[test]
    fn test_create_decoding_key_for_supabase_auth() {
        // 测试 Supabase Auth 标准的 ECC P-256 JWK
        let jwk = create_test_jwk();
        let result = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            result.is_ok(),
            "Should create decoding key from valid Supabase Auth JWK (ECC P-256)"
        );

        // 测试无效的 JWK (缺少 ECC P-256 必要坐标)
        let mut invalid_jwk = create_test_jwk();
        invalid_jwk.x = None; // 缺少 P-256 椭圆曲线的 x 坐标
        let result = parser::JwtParser::create_decoding_key(&invalid_jwk);
        assert!(
            matches!(result, Err(AuthError::InvalidKeyComponent(_))),
            "Should reject JWK missing x coordinate for ECC P-256"
        );
    }

    #[test]
    fn test_parse_algorithm() {
        // 支持的算法
        let result = parser::JwtParser::parse_algorithm("ES256");
        assert!(result.is_ok(), "ES256 algorithm should be supported");
        assert_eq!(
            result.expect("Should parse ES256 algorithm"),
            Algorithm::ES256
        );

        // 不支持的算法 (Supabase Auth 专用，仅支持 ES256)
        assert!(
            parser::JwtParser::parse_algorithm("RS256").is_err(),
            "RS256 not supported by Supabase Auth"
        );
        assert!(
            parser::JwtParser::parse_algorithm("HS256").is_err(),
            "HS256 not supported by Supabase Auth"
        );
        assert!(
            parser::JwtParser::parse_algorithm("PS256").is_err(),
            "PS256 not supported by Supabase Auth"
        );
        assert!(
            parser::JwtParser::parse_algorithm("ES384").is_err(),
            "ES384 not supported by Supabase Auth"
        );
        assert!(
            parser::JwtParser::parse_algorithm("ES512").is_err(),
            "ES512 not supported by Supabase Auth"
        );
        assert!(
            parser::JwtParser::parse_algorithm("none").is_err(),
            "'none' algorithm forbidden for security"
        );
        assert!(
            parser::JwtParser::parse_algorithm("INVALID").is_err(),
            "Invalid algorithm should not be supported"
        );
        assert!(
            parser::JwtParser::parse_algorithm("").is_err(),
            "Empty algorithm should not be supported"
        );

        // 测试大小写敏感性 (Supabase Auth 要求严格匹配 "ES256")
        assert!(
            parser::JwtParser::parse_algorithm("es256").is_err(),
            "Should reject lowercase es256"
        );
        assert!(
            parser::JwtParser::parse_algorithm("Es256").is_err(),
            "Should reject mixed case Es256"
        );
        assert!(
            parser::JwtParser::parse_algorithm("ES256").is_ok(),
            "Should accept exact ES256"
        );
    }

    #[test]
    fn test_verify_and_decode_failure_invalid_signature() {
        let jwk = create_test_jwk();
        let decoding_key = parser::JwtParser::create_decoding_key(&jwk)
            .expect("Should create decoding key from valid JWK");
        let algorithm =
            parser::JwtParser::parse_algorithm("ES256").expect("Should parse ES256 algorithm");

        // 使用一个带有无效签名的token
        let invalid_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJzdWIiOiJ0ZXN0In0.invalidsignature";
        let result = parser::JwtParser::verify_and_decode(invalid_token, &decoding_key, algorithm);
        assert!(
            result.is_err(),
            "JWT validation should fail with an invalid signature"
        );

        // 测试完全无效的签名格式
        let malformed_token =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJzdWIiOiJ0ZXN0In0.";
        let result2 =
            parser::JwtParser::verify_and_decode(malformed_token, &decoding_key, algorithm);
        assert!(
            result2.is_err(),
            "JWT validation should fail with empty signature"
        );
    }

    // ==================== 错误处理测试 ====================

    #[test]
    fn test_algorithm_errors() {
        let result = parser::JwtParser::parse_algorithm("INVALID");
        assert!(matches!(result, Err(AuthError::InvalidAlgorithm)));
    }

    #[test]
    fn test_header_parsing_errors() {
        let result = parser::JwtParser::decode_header("");
        assert!(result.is_err(), "Empty token should cause an error");
        // 接受任何错误类型，因为空字符串可能触发不同的错误路径
    }

    #[test]
    fn test_jwk_validation_errors() {
        let mut invalid_jwk = create_test_jwk();
        invalid_jwk.x = None;

        let result = parser::JwtParser::create_decoding_key(&invalid_jwk);
        assert!(matches!(result, Err(AuthError::InvalidKeyComponent(_))));
    }

    // ==================== 基本验证测试 ====================

    #[test]
    fn test_algorithm_support() {
        // 测试支持的 ES256 算法
        let result = parser::JwtParser::parse_algorithm("ES256");
        assert!(result.is_ok());

        // 测试不支持的算法（基于前置条件，只支持ES256）
        let unsupported = vec!["HS256", "RS256", "PS256"];
        for alg in unsupported {
            let result = parser::JwtParser::parse_algorithm(alg);
            assert!(
                result.is_err(),
                "Should reject unsupported algorithm: {alg}"
            );
        }
    }

    #[test]
    fn test_supabase_jwk_coordinate_validation() {
        let mut jwk = create_test_jwk();

        // 测试缺少 ECC P-256 必要坐标的情况
        jwk.x = None;
        let result = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result, Err(AuthError::InvalidKeyComponent(_))),
            "Should reject JWK missing x coordinate for Supabase Auth ECC P-256"
        );

        // 恢复正确的 x 坐标，测试缺少 y 坐标
        jwk.x = Some("ykCi3ZomyYBFS21ZKk6ajc56O1SUFzhCNp0ziDYd6mw".to_string());
        jwk.y = None;
        let result = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result, Err(AuthError::InvalidKeyComponent(_))),
            "Should reject JWK missing y coordinate for Supabase Auth ECC P-256"
        );
    }

    // ==================== 边界条件和安全测试 ====================

    #[test]
    fn test_decode_header_malformed_base64() {
        // 测试无效的 base64 编码
        let invalid_token = "invalid_base64!@#.payload.signature";
        let result = parser::JwtParser::decode_header(invalid_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_header_invalid_json() {
        // 创建一个有效的 base64 但无效的 JSON
        let invalid_json_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{invalid json}");
        let invalid_token = format!("{invalid_json_b64}.payload.signature");
        let result = parser::JwtParser::decode_header(&invalid_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_header_unsupported_algorithm() {
        // 创建一个包含不支持算法的 header
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": "test-key-id"
        });
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let token = format!("{header_b64}.payload.signature");

        let result = parser::JwtParser::decode_header(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_decoding_key_unsupported_curve() {
        let mut jwk = create_test_jwk();
        jwk.crv = Some("P-384".to_string()); // Supabase Auth 不支持的椭圆曲线

        let result = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result, Err(AuthError::UnsupportedCurve(_))),
            "Should reject P-384 curve (Supabase Auth only supports P-256)"
        );

        // 测试其他不支持的椭圆曲线
        jwk.crv = Some("P-521".to_string());
        let result2 = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result2, Err(AuthError::UnsupportedCurve(_))),
            "Should reject P-521 curve (Supabase Auth only supports P-256)"
        );

        jwk.crv = Some("secp256k1".to_string()); // Bitcoin 使用的曲线
        let result3 = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result3, Err(AuthError::UnsupportedCurve(_))),
            "Should reject secp256k1 curve (Supabase Auth only supports P-256)"
        );
    }

    #[test]
    fn test_create_decoding_key_invalid_coordinate_length() {
        let mut jwk = create_test_jwk();
        // 使用错误长度的坐标（Supabase Auth ECC P-256 需要精确的 32 字节坐标）
        jwk.x = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"short"));

        let result = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result, Err(AuthError::InvalidKeyComponent(_))),
            "Should reject invalid coordinate length for Supabase Auth ECC P-256"
        );

        // 测试过长的坐标
        jwk.x = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 64])); // 64 字节，超过 P-256 的 32 字节
        let result2 = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result2, Err(AuthError::InvalidKeyComponent(_))),
            "Should reject oversized coordinate for Supabase Auth ECC P-256"
        );
    }

    #[test]
    fn test_create_decoding_key_unsupported_key_type() {
        let mut jwk = create_test_jwk();
        jwk.kty = "RSA".to_string(); // Supabase Auth 不支持的密钥类型

        let result = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result, Err(AuthError::UnsupportedKeyType(_))),
            "Should reject RSA key type (Supabase Auth only supports EC)"
        );

        // 测试其他不支持的密钥类型
        jwk.kty = "oct".to_string(); // 对称密钥
        let result2 = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result2, Err(AuthError::UnsupportedKeyType(_))),
            "Should reject symmetric key type (Supabase Auth only supports EC)"
        );

        jwk.kty = "OKP".to_string(); // Octet Key Pair (Ed25519 等)
        let result3 = parser::JwtParser::create_decoding_key(&jwk);
        assert!(
            matches!(result3, Err(AuthError::UnsupportedKeyType(_))),
            "Should reject OKP key type (Supabase Auth only supports EC)"
        );
    }

    #[test]
    fn test_decode_header_with_special_characters() {
        // 测试包含特殊字符的 token
        let token_with_special_chars = "header.payload.signature@#$%";
        let result = parser::JwtParser::decode_header(token_with_special_chars);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_header_maximum_length() {
        // 测试接近最大长度限制的 token
        let long_part = "a".repeat(2700); // 接近 8KB / 3
        let long_token = format!("{long_part}.{long_part}.{long_part}");

        let result = parser::JwtParser::decode_header(&long_token);
        assert!(
            result.is_err(),
            "Token exceeding maximum length should be rejected"
        );

        // 测试正好在边界的情况
        let boundary_length = 8192;
        let boundary_token = "a".repeat(boundary_length);
        let result2 = parser::JwtParser::decode_header(&boundary_token);
        assert!(
            result2.is_err(),
            "Token at exact boundary length should be rejected"
        );

        // 测试稍微超过边界的情况
        let over_boundary_token = "a".repeat(boundary_length + 1);
        let result3 = parser::JwtParser::decode_header(&over_boundary_token);
        assert!(
            result3.is_err(),
            "Token slightly over boundary should be rejected"
        );

        // 验证错误类型
        match result {
            Err(AuthError::DecodeHeader) => {} // 预期的错误类型
            _ => panic!("Expected DecodeHeader error for oversized token"),
        }
    }

    #[test]
    fn test_jwk_validation_comprehensive() {
        // 测试完整的 JWK 验证
        let jwk = create_test_jwk();

        // 验证 JWK 的基本属性
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.alg, Some("ES256".to_string()));
        assert_eq!(jwk.crv, Some("P-256".to_string()));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());

        // 测试创建解码密钥
        let result = parser::JwtParser::create_decoding_key(&jwk);
        assert!(result.is_ok());
    }

    #[test]
    fn test_supabase_algorithm_parsing_edge_cases() {
        // 测试 Supabase Auth 支持的唯一算法：ES256 (ECC P-256)
        assert_eq!(
            parser::JwtParser::parse_algorithm("ES256").expect("Should parse ES256"),
            Algorithm::ES256
        );

        // 测试 Supabase Auth 不支持的其他椭圆曲线算法
        assert!(
            parser::JwtParser::parse_algorithm("ES384").is_err(),
            "ES384 not supported by Supabase Auth (uses P-384)"
        );
        assert!(
            parser::JwtParser::parse_algorithm("ES512").is_err(),
            "ES512 not supported by Supabase Auth (uses P-521)"
        );

        // 测试其他常见但不支持的算法
        assert!(
            parser::JwtParser::parse_algorithm("HS256").is_err(),
            "HS256 not supported by Supabase Auth"
        );
        assert!(
            parser::JwtParser::parse_algorithm("RS256").is_err(),
            "RS256 not supported by Supabase Auth"
        );
        assert!(
            parser::JwtParser::parse_algorithm("PS256").is_err(),
            "PS256 not supported by Supabase Auth"
        );
        assert!(
            parser::JwtParser::parse_algorithm("INVALID").is_err(),
            "Invalid algorithm should be rejected"
        );
        assert!(
            parser::JwtParser::parse_algorithm("").is_err(),
            "Empty algorithm should be rejected"
        );

        // 测试安全相关的特殊情况
        assert!(
            parser::JwtParser::parse_algorithm("none").is_err(),
            "'none' algorithm forbidden for security"
        );
        assert!(
            parser::JwtParser::parse_algorithm(" ES256 ").is_err(),
            "Algorithm with whitespace should be rejected"
        );
        assert!(
            parser::JwtParser::parse_algorithm("ES256\0").is_err(),
            "Algorithm with null byte should be rejected"
        );
    }

    #[test]
    fn test_header_parsing_security() {
        // 测试恶意构造的 header
        let malicious_headers = vec![
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",  // alg: none
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", // HS256
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", // RS256
        ];

        for header in malicious_headers {
            let token = format!("{header}.payload.signature");
            let result = parser::JwtParser::decode_header(&token);

            // 应该能解析 header，但算法验证会在后续步骤失败
            if result.is_ok() {
                let parsed_header = result.unwrap();
                // 验证不支持的算法会在 parse_algorithm 中被拒绝
                if parsed_header.alg != "ES256" {
                    assert!(parser::JwtParser::parse_algorithm(&parsed_header.alg).is_err());
                }
            }
        }
    }

    #[test]
    fn test_jwk_coordinate_edge_cases() {
        let mut jwk = create_test_jwk();

        // 测试缺失坐标
        jwk.x = None;
        assert!(matches!(
            parser::JwtParser::create_decoding_key(&jwk),
            Err(AuthError::InvalidKeyComponent(_))
        ));

        jwk = create_test_jwk();
        jwk.y = None;
        assert!(matches!(
            parser::JwtParser::create_decoding_key(&jwk),
            Err(AuthError::InvalidKeyComponent(_))
        ));

        // 测试无效的坐标长度
        jwk = create_test_jwk();
        jwk.x = Some("short".to_string());
        // "short" is not valid base64, so it should fail at the decoding stage
        assert!(matches!(
            parser::JwtParser::create_decoding_key(&jwk),
            Err(AuthError::Base64Decode(_))
        ));

        // 测试无效的 base64
        jwk = create_test_jwk();
        jwk.x = Some("invalid_base64!".to_string());
        assert!(matches!(
            parser::JwtParser::create_decoding_key(&jwk),
            Err(AuthError::Base64Decode(_))
        ));
    }

    #[test]
    fn test_token_format_variations() {
        // 测试各种无效的 token 格式
        let invalid_tokens = vec![
            ("", "empty token"),
            ("single_part", "single part token"),
            ("two.parts", "two parts token"),
            ("too.many.parts.here.invalid", "five parts token"),
            ("...", "three empty parts"),
            ("valid..", "empty payload and signature"),
            (".valid.", "empty header and signature"),
            ("..valid", "empty header and payload"),
            ("a.b.c.d.e.f", "six parts token"),
            (".", "single dot"),
            ("..", "two dots only"),
        ];

        for (token, description) in invalid_tokens {
            let result = parser::JwtParser::decode_header(token);
            assert!(
                result.is_err(),
                "Token '{token}' ({description}) should be invalid"
            );

            // 验证错误类型
            match result {
                Err(_) => {} // 接受任何错误类型，因为不同格式错误可能返回不同错误
                _ => panic!("Expected error for token: {token}"),
            }
        }
    }

    #[test]
    fn test_supabase_parser_performance_and_security() {
        // 测试 Supabase Auth JWT 解析器的性能稳定性
        // 验证大量 ES256 (ECC P-256) token 解析的性能
        let valid_token = create_mock_jwt_token();
        let start = std::time::Instant::now();

        for _ in 0..1000 {
            let result = parser::JwtParser::decode_header(&valid_token);
            assert!(
                result.is_ok(),
                "Valid Supabase Auth token should always be parsed successfully"
            );
        }

        let duration = start.elapsed();
        assert!(duration.as_millis() < 100, "1000 Supabase Auth JWT header parsing operations should complete within 100ms, took: {duration:?}");

        // 测试恶意构造的 token 不会导致 Supabase Auth 解析器性能问题
        // 确保 DoS 攻击防护有效
        let malicious_tokens = vec![
            format!(
                "{}.{}.{}",
                "a".repeat(8000),
                "b".repeat(8000),
                "c".repeat(8000)
            ), // 接近最大长度的恶意 token
            format!("header.{}.signature", "x".repeat(7000)), // 超长 payload 攻击
            format!("{}.payload.signature", "y".repeat(7000)), // 超长 header 攻击
        ];

        for malicious_token in &malicious_tokens {
            let start = std::time::Instant::now();
            let result = parser::JwtParser::decode_header(malicious_token);
            let duration = start.elapsed();

            assert!(
                result.is_err(),
                "Malicious token should be rejected by Supabase Auth parser"
            );
            assert!(
                duration.as_millis() < 10,
                "Supabase Auth parser should quickly reject malicious tokens, took: {duration:?}"
            );
        }
    }

    #[test]
    fn test_supabase_unicode_and_encoding_edge_cases() {
        // 测试 Supabase Auth 解析器对包含 Unicode 字符的 token 的处理
        // Supabase Auth 标准 JWT 应该只包含 base64url 字符
        let unicode_tokens = vec![
            "header.payload.签名",     // 中文字符 (非 base64url)
            "header.payload.🔐",       // Emoji (非 base64url)
            "header.payload.\u{0000}", // Null 字符 (安全风险)
            "header.payload.\u{FEFF}", // BOM 字符 (编码问题)
            "header.payload.\u{200B}", // 零宽空格 (隐藏字符)
        ];

        for token in unicode_tokens {
            let result = parser::JwtParser::decode_header(token);
            assert!(
                result.is_err(),
                "Supabase Auth parser should reject token with Unicode characters: {token}"
            );
        }

        // 测试包含控制字符的 token (安全防护)
        // Supabase Auth JWT 不应包含任何控制字符
        let control_char_tokens = vec![
            "header.payload.\x00signature", // Null byte (安全风险)
            "header.payload.\x01signature", // SOH (控制字符)
            "header.payload.\x1Fsignature", // Unit separator (控制字符)
            "header\x0A.payload.signature", // Newline in header (格式破坏)
            "header.payload\x0D.signature", // Carriage return in payload (格式破坏)
        ];

        for token in control_char_tokens {
            let result = parser::JwtParser::decode_header(token);
            assert!(
                result.is_err(),
                "Supabase Auth parser should reject token with control characters"
            );
        }
    }

    #[test]
    fn test_supabase_base64_padding_variations() {
        // 测试 Supabase Auth JWT 的 base64url 编码处理
        // 标准 JWT 使用 base64url 编码，不应包含填充字符
        // 根据 RFC 7515，base64url 编码不使用填充字符，应该被拒绝
        let padding_test_cases = vec![
            ("header=.payload.signature", "header with padding"),
            ("header.payload=.signature", "payload with padding"),
            ("header.payload.signature=", "signature with padding"),
            ("header==.payload.signature", "header with double padding"),
            ("header.payload==.signature", "payload with double padding"),
            (
                "header.payload.signature==",
                "signature with double padding",
            ),
        ];

        for (token, description) in padding_test_cases {
            let result = parser::JwtParser::decode_header(token);
            // 根据 RFC 7515 标准，base64url 编码不应包含填充字符
            // 严格的实现应该拒绝包含填充字符的 token
            assert!(
                result.is_err(),
                "Supabase Auth JWT parser should reject token with padding characters: {description}"
            );

            // 确保错误类型是 Unauthorized（而不是其他类型的错误）
            if let Err(error) = result {
                // 接受 DecodeHeader 或其他相关错误类型
                assert!(
                    matches!(error, AuthError::DecodeHeader | AuthError::InvalidToken),
                    "Expected DecodeHeader or InvalidToken error for {description}, got: {error:?}"
                );
            }
        }
    }
}
