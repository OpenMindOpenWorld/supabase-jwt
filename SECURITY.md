# Security Policy

## 🔒 Supported Versions

We actively support the following versions of `supabase-jwt` with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## 🚨 Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in `supabase-jwt`, please report it to us privately. We take all security reports seriously and will respond promptly.

### How to Report

1. **Email**: Send details to [kkanata996@gmail.com](mailto:kkanata996@gmail.com)
2. **Subject**: Use "[SECURITY] supabase-jwt vulnerability report"
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes (if available)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 5 business days
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical issues within 30 days
- **Credit**: We will credit you in our security advisory (unless you prefer to remain anonymous)

## 🛡️ Security Best Practices

When using `supabase-jwt`, please follow these security best practices:

### JWT Token Handling

- **Never log JWT tokens** in production environments
- **Use HTTPS only** when transmitting tokens
- **Implement proper token expiration** checking
- **Validate all claims** before trusting token data
- **Store tokens securely** on the client side (avoid localStorage for sensitive apps)

### JWKS Configuration

- **Use HTTPS URLs** for JWKS endpoints
- **Implement proper caching** to avoid excessive requests
- **Monitor JWKS endpoint availability** in production
- **Validate JWKS responses** before using keys

### Error Handling

- **Don't expose sensitive information** in error messages
- **Log security events** for monitoring
- **Implement rate limiting** for token validation endpoints
- **Use structured logging** for security analysis

### Example Secure Usage

```rust
use supabase_jwt::{Claims, JwksCache};
use tracing::{info, warn, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ✅ Use HTTPS for JWKS URL
    let jwks_url = "https://your-project.supabase.co/auth/v1/jwks";
    let jwks_cache = JwksCache::new(jwks_url);
    
    // ✅ Validate token from secure source
    let bearer_token = get_token_from_secure_header()?;
    
    match Claims::from_bearer_token(&bearer_token, &jwks_cache).await {
        Ok(claims) => {
            // ✅ Log successful authentication (without token data)
            info!("User authenticated: {}", claims.user_id());
            
            // ✅ Validate token expiration
            if claims.is_expired() {
                warn!("Expired token used");
                return Err("Token expired".into());
            }
            
            // ✅ Use claims safely
            process_authenticated_request(claims).await?;
        }
        Err(e) => {
            // ✅ Log security event without exposing sensitive data
            warn!("Authentication failed: {}", e);
            return Err("Authentication failed".into());
        }
    }
    
    Ok(())
}

// ✅ Don't expose tokens in logs or errors
fn get_token_from_secure_header() -> Result<String, Box<dyn std::error::Error>> {
    // Implementation that securely extracts token
    todo!()
}

async fn process_authenticated_request(claims: Claims) -> Result<(), Box<dyn std::error::Error>> {
    // Process request with validated claims
    todo!()
}
```

## 🔍 Security Features

This library implements several security measures:

- **Algorithm Validation**: Only accepts ES256 algorithm (Supabase standard)
- **Key Validation**: Validates JWKS key format and parameters
- **Signature Verification**: Cryptographic signature validation
- **Expiration Checking**: Built-in token expiration validation
- **Issuer Validation**: Validates token issuer claims
- **Audience Validation**: Supports audience claim validation
- **Memory Safety**: Written in Rust for memory safety guarantees

## 📋 Security Checklist for Integrators

Before deploying `supabase-jwt` in production:

- [ ] Verify JWKS URL uses HTTPS
- [ ] Implement proper error handling
- [ ] Set up security logging and monitoring
- [ ] Configure appropriate token caching policies
- [ ] Test token validation with expired/invalid tokens
- [ ] Implement rate limiting for authentication endpoints
- [ ] Review and audit your integration code
- [ ] Set up alerts for authentication failures
- [ ] Document your security procedures
- [ ] Plan for security incident response

## 🚀 Staying Updated

To stay informed about security updates:

- **Watch this repository** for security advisories
- **Subscribe to releases** to get notified of updates
- **Follow our changelog** for security-related changes
- **Enable Dependabot** to get automatic dependency updates

## 📞 Contact

For security-related questions or concerns:

- **Security Issues**: [kkanata996@gmail.com](mailto:kkanata996@gmail.com)
- **General Questions**: [GitHub Issues](https://github.com/OpenMindOpenWorld/supabase-jwt/issues)
- **Documentation**: [README.md](README.md)

## 🙏 Acknowledgments

We thank the security research community for helping keep `supabase-jwt` secure. If you've reported a security issue, we appreciate your responsible disclosure.

---

**Note**: This security policy is subject to updates. Please check back regularly for the latest information.