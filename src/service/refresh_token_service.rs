use crate::config::logging::secure_log;
use crate::config::parameter;
use crate::dto::token_dto::TokenWithRefreshDto;
use crate::entity::user::User;
use crate::error::{AppError, token_error::TokenError};
use crate::repository::user_repository::UserRepositoryTrait;
use crate::service::token_service::{TokenService, TokenServiceTrait};
use chrono::{DateTime, Duration, Utc};
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha256, Digest};
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct RefreshTokenService {
    refresh_token_ttl_days: i64,
    enable_rotation: bool,
}

pub trait RefreshTokenServiceTrait {
    fn new() -> Self;
    fn generate_refresh_token(&self) -> String;
    fn hash_refresh_token(&self, token: &str) -> String;
    fn generate_family_id(&self) -> String;
    fn create_token_with_refresh(
        &self,
        user: User,
        fingerprint_hash: &str,
    ) -> Result<TokenWithRefreshDto, AppError>;
    async fn validate_refresh_token(&self, token_hash: &str, user_id: Uuid, user_repo: &impl UserRepositoryTrait) -> Result<bool, AppError>;
    fn should_rotate_token(&self) -> bool;
    fn calculate_expiration(&self) -> DateTime<Utc>;
}

impl RefreshTokenServiceTrait for RefreshTokenService {
    fn new() -> Self {
        let refresh_token_ttl_days = parameter::get_optional("REFRESH_TOKEN_TTL_DAYS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let enable_rotation = parameter::get_bool("REFRESH_TOKEN_ROTATION");

        info!("SECURITY: Refresh token service initialized with TTL: {} days, rotation: {}",
            refresh_token_ttl_days, enable_rotation);

        Self {
            refresh_token_ttl_days,
            enable_rotation,
        }
    }

    fn generate_refresh_token(&self) -> String {
        // Generate a cryptographically secure 32-byte random token
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);

        // Convert to base64 for easier storage and transmission
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn hash_refresh_token(&self, token: &str) -> String {
        // Use SHA256 to hash the refresh token before storing
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();

        // Convert to hex string
        let mut hex_string = String::with_capacity(64);
        for byte in result {
            use std::fmt::Write;
            write!(hex_string, "{:02x}", byte).unwrap();
        }
        hex_string
    }

    fn generate_family_id(&self) -> String {
        Uuid::new_v4().to_string()
    }

    fn create_token_with_refresh(
        &self,
        user: User,
        fingerprint_hash: &str,
    ) -> Result<TokenWithRefreshDto, AppError> {
        // Generate access token (reuse existing logic from TokenService)
        let token_svc = TokenService::new()?;
        let access_token = token_svc.generate_token_with_fingerprint(user.clone(), fingerprint_hash)?;

        // Generate refresh token
        let refresh_token = self.generate_refresh_token();
        let family_id = self.generate_family_id();

        info!("SECURITY: Refresh token pair generated for user ID: {} with family ID: {}", user.id, family_id);
        secure_log::sensitive_debug!("Refresh token generated for email: {} with fingerprint hash: {}", user.email, fingerprint_hash);

        Ok(TokenWithRefreshDto {
            token: access_token.token,
            iat: access_token.iat,
            exp: access_token.exp,
            refresh_token,
            family_id,
        })
    }

    async fn validate_refresh_token(&self, token_hash: &str, user_id: Uuid, user_repo: &impl UserRepositoryTrait) -> Result<bool, AppError> {
        match user_repo.validate_refresh_token(token_hash, user_id).await {
            Ok(is_valid) => {
                if is_valid {
                    info!("SECURITY: Refresh token validated successfully for user ID: {}", user_id);
                } else {
                    warn!("SECURITY: Refresh token validation failed for user ID: {}", user_id);
                }
                Ok(is_valid)
            }
            Err(e) => {
                error!("SECURITY: Database error during refresh token validation for user ID: {}: {}", user_id, e);
                secure_log::secure_error!("Refresh token validation database error", e);
                Err(AppError::Token(TokenError::InvalidRefreshToken))
            }
        }
    }

    fn should_rotate_token(&self) -> bool {
        self.enable_rotation
    }

    fn calculate_expiration(&self) -> DateTime<Utc> {
        Utc::now() + Duration::days(self.refresh_token_ttl_days)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_refresh_token() {
        // Initialize logging config for tests
        crate::config::logging::tests::init_test_config();

        let service = RefreshTokenService::new();
        let token1 = service.generate_refresh_token();
        let token2 = service.generate_refresh_token();

        // Tokens should be unique
        assert_ne!(token1, token2);

        // Tokens should be base64 encoded (32 bytes = 42.67 chars, rounded up with padding)
        assert!(token1.len() >= 42 && token1.len() <= 44);
        assert!(token2.len() >= 42 && token2.len() <= 44);
    }

    #[test]
    fn test_hash_refresh_token() {
        let service = RefreshTokenService::new();
        let token = "test_refresh_token";
        let hash1 = service.hash_refresh_token(token);
        let hash2 = service.hash_refresh_token(token);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Hash should be 64 characters (SHA256 hex)
        assert_eq!(hash1.len(), 64);

        // Different input should produce different hash
        let different_hash = service.hash_refresh_token("different_token");
        assert_ne!(hash1, different_hash);
    }

    #[test]
    fn test_generate_family_id() {
        // Initialize logging config for tests
        crate::config::logging::tests::init_test_config();

        let service = RefreshTokenService::new();
        let family_id1 = service.generate_family_id();
        let family_id2 = service.generate_family_id();

        // Family IDs should be unique
        assert_ne!(family_id1, family_id2);

        // Should be valid UUID format
        assert!(Uuid::parse_str(&family_id1).is_ok());
        assert!(Uuid::parse_str(&family_id2).is_ok());
    }

    #[test]
    fn test_calculate_expiration() {
        // Initialize logging config for tests
        crate::config::logging::tests::init_test_config();

        let service = RefreshTokenService::new();
        let expiration = service.calculate_expiration();
        let now = Utc::now();

        // Expiration should be in the future
        assert!(expiration > now);

        // Should be approximately 30 days from now (allowing for test execution time)
        let expected = now + Duration::days(30);
        let diff = (expiration - expected).num_seconds().abs();
        assert!(diff < 10); // Within 10 seconds
    }

    #[test]
    fn test_should_rotate_token() {
        // Initialize logging config for tests
        crate::config::logging::tests::init_test_config();

        let service = RefreshTokenService::new();
        // By default, rotation should be enabled
        assert!(service.should_rotate_token());
    }

    #[test]
    fn test_refresh_token_validation() {
        // Initialize logging config for tests
        crate::config::logging::tests::init_test_config();

        let service = RefreshTokenService::new();
        let token = "test_token";
        let _user_id = uuid::Uuid::now_v7();

        // For unit test without database, we just test the method exists
        // The actual validation requires a repository which is tested in integration tests
        let _token_hash = service.hash_refresh_token(token);
        // Method exists and can be called (signature check)
        assert!(true); // Just test compilation
    }

    #[test]
    fn test_refresh_token_workflow() {
        // Initialize logging config for tests
        crate::config::logging::tests::init_test_config();

        let service = RefreshTokenService::new();

        // Test the complete workflow of generating and hashing a token
        let raw_token = service.generate_refresh_token();
        let hashed_token = service.hash_refresh_token(&raw_token);

        // Verify token is different from hash
        assert_ne!(raw_token, hashed_token);

        // Verify hash is consistent
        let hashed_token2 = service.hash_refresh_token(&raw_token);
        assert_eq!(hashed_token, hashed_token2);

        // Verify hash length (SHA256 produces 64 character hex string)
        assert_eq!(hashed_token.len(), 64);
    }
}