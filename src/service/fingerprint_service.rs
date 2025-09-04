use async_trait::async_trait;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use dashmap::DashMap;
use crate::config::logging::{secure_log};
use crate::config::parameter;

/// Fingerprint data structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintData {
    pub user_id: Uuid,
    pub fingerprint_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Trait for fingerprint storage implementations
/// This allows easy switching between in-memory, Redis, or database storage
#[async_trait]
pub trait FingerprintStore: Send + Sync {
    /// Store a fingerprint with TTL
    async fn store_fingerprint(
        &self,
        user_id: Uuid,
        fingerprint_hash: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl_minutes: i64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Validate a fingerprint for a user
    async fn validate_fingerprint(
        &self,
        fingerprint_hash: &str,
        expected_user_id: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;

    /// Clean up expired fingerprints
    async fn cleanup_expired(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>>;
}

/// Fingerprint service for generation and hashing
pub struct FingerprintService;

impl FingerprintService {
    /// Generate a cryptographically secure random fingerprint
    pub fn generate_fingerprint() -> String {
        use rand::{RngCore, rngs::OsRng};

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);

        // Convert to base64 for easier storage and transmission
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// Hash a fingerprint using SHA256
    pub fn hash_fingerprint(fingerprint: &str) -> String {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(fingerprint.as_bytes());

        // Use more efficient hex encoding
        let result = hasher.finalize();
        let mut hex_string = String::with_capacity(64); // SHA256 produces 32 bytes = 64 hex chars

        for byte in result {
            use std::fmt::Write;
            if let Err(e) = write!(hex_string, "{:02x}", byte) {
                secure_log::secure_error!("Failed to write hex byte to string buffer", e);
                // Return a fallback hash if encoding fails (extremely rare)
                return format!("{:x}", result);
            }
        }

        hex_string
    }

    /// Create an HttpOnly cookie for the fingerprint
    pub fn create_fingerprint_cookie(fingerprint: &str) -> String {
        let max_age_days = parameter::get_optional("FINGERPRINT_COOKIE_MAX_AGE_DAYS")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30); // Default to 30 days if not configured
        let max_age_seconds = max_age_days * 24 * 60 * 60;

        format!(
            "user_fingerprint={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
            fingerprint,
            max_age_seconds
        )
    }

    /// Extract fingerprint from cookie header
    pub fn extract_fingerprint_from_cookie(cookie_header: &str) -> Option<String> {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some((name, value)) = cookie.split_once('=')
                && name.trim() == "user_fingerprint" {
                return Some(value.trim().to_string());
            }
        }
        None
    }
}

/// In-memory implementation of FingerprintStore using DashMap for better concurrency
pub struct InMemoryFingerprintStore {
    fingerprints: Arc<DashMap<String, FingerprintData>>,
}

impl InMemoryFingerprintStore {
    pub fn new() -> Self {
        Self {
            fingerprints: Arc::new(DashMap::new()),
        }
    }

    /// Create a new instance wrapped in Arc for sharing across threads
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

#[async_trait]
impl FingerprintStore for InMemoryFingerprintStore {
    async fn store_fingerprint(
        &self,
        user_id: Uuid,
        fingerprint_hash: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
        ttl_minutes: i64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fingerprint_data = FingerprintData {
            user_id,
            fingerprint_hash: fingerprint_hash.to_string(),
            ip_address,
            user_agent,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(ttl_minutes),
        };

        self.fingerprints.insert(fingerprint_hash.to_string(), fingerprint_data);
        Ok(())
    }

    async fn validate_fingerprint(
        &self,
        fingerprint_hash: &str,
        expected_user_id: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(fingerprint) = self.fingerprints.get(fingerprint_hash) {
            // Check if expired
            if Utc::now() > fingerprint.expires_at {
                secure_log::secure_error!("SECURITY: Fingerprint validation failed - expired fingerprint for user ID: {}", expected_user_id);
                return Ok(false);
            }

            // Check if user matches
            if fingerprint.user_id == expected_user_id {
                tracing::info!("SECURITY: Fingerprint validation successful for user ID: {}", expected_user_id);
                return Ok(true);
            } else {
                secure_log::secure_error!("SECURITY: Fingerprint validation failed - user mismatch for user ID: {} (expected: {}, found: {})", expected_user_id, expected_user_id, fingerprint.user_id);
            }
        } else {
            secure_log::secure_error!("SECURITY: Fingerprint validation failed - fingerprint not found for user ID: {}", expected_user_id);
        }

        Ok(false)
    }

    async fn cleanup_expired(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let now = Utc::now();
        let mut cleaned_count = 0;

        // Collect keys to remove to avoid borrowing issues
        let keys_to_remove: Vec<String> = self.fingerprints
            .iter()
            .filter(|entry| entry.value().expires_at <= now)
            .map(|entry| entry.key().clone())
            .collect();

        // Remove expired entries
        for key in keys_to_remove {
            if self.fingerprints.remove(&key).is_some() {
                cleaned_count += 1;
            }
        }

        Ok(cleaned_count)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fingerprint_generation() {
        let fingerprint1 = FingerprintService::generate_fingerprint();
        let fingerprint2 = FingerprintService::generate_fingerprint();

        // Fingerprints should be unique
        assert_ne!(fingerprint1, fingerprint2);

        // Fingerprints should be base64 encoded (32 bytes = 42.67 chars, rounded up with padding)
        assert!(fingerprint1.len() >= 42 && fingerprint1.len() <= 44);
        assert!(fingerprint2.len() >= 42 && fingerprint2.len() <= 44);
    }

    #[tokio::test]
    async fn test_fingerprint_hashing() {
        let fingerprint = "test_fingerprint_data";
        let hash1 = FingerprintService::hash_fingerprint(fingerprint);
        let hash2 = FingerprintService::hash_fingerprint(fingerprint);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Hash should be 64 characters (SHA256 hex)
        assert_eq!(hash1.len(), 64);

        // Different input should produce different hash
        let different_hash = FingerprintService::hash_fingerprint("different_data");
        assert_ne!(hash1, different_hash);
    }

    #[tokio::test]
    async fn test_fingerprint_cookie_creation() {
        let fingerprint = "test_fingerprint_123";
        let cookie = FingerprintService::create_fingerprint_cookie(fingerprint);

        assert!(cookie.contains("user_fingerprint=test_fingerprint_123"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age="));
    }

    #[tokio::test]
    async fn test_fingerprint_cookie_extraction() {
        let cookie_header = "session_id=abc123; user_fingerprint=test_fp_456; other=value";
        let fingerprint = FingerprintService::extract_fingerprint_from_cookie(cookie_header);

        assert_eq!(fingerprint, Some("test_fp_456".to_string()));
    }

    #[tokio::test]
    async fn test_fingerprint_cookie_extraction_no_fingerprint() {
        let cookie_header = "session_id=abc123; other=value";
        let fingerprint = FingerprintService::extract_fingerprint_from_cookie(cookie_header);

        assert_eq!(fingerprint, None);
    }

    #[tokio::test]
    async fn test_in_memory_fingerprint_store() {
        // Initialize logging for tests
        let _ = crate::config::logging::init();

        let store = InMemoryFingerprintStore::new();
        let user_id = uuid::Uuid::new_v4();
        let fingerprint_hash = "test_hash_123";

        // Test storing fingerprint
        let result = store.store_fingerprint(
            user_id,
            fingerprint_hash,
            Some("192.168.1.1".to_string()),
            Some("Mozilla/5.0".to_string()),
            30,
        ).await;

        assert!(result.is_ok());

        // Test validating fingerprint
        let is_valid = store.validate_fingerprint(fingerprint_hash, user_id).await.unwrap();
        assert!(is_valid);

        // Test validating with wrong user ID
        let wrong_user_id = uuid::Uuid::new_v4();
        let is_valid_wrong = store.validate_fingerprint(fingerprint_hash, wrong_user_id).await.unwrap();
        assert!(!is_valid_wrong);

        // Test validating non-existent fingerprint
        let is_valid_nonexistent = store.validate_fingerprint("nonexistent", user_id).await.unwrap();
        assert!(!is_valid_nonexistent);
    }

    #[tokio::test]
    async fn test_fingerprint_expiration() {
        // Initialize logging for tests
        let _ = crate::config::logging::init();

        let store = InMemoryFingerprintStore::new();
        let user_id = uuid::Uuid::new_v4();
        let fingerprint_hash = "test_hash_expire";

        // Store fingerprint with TTL
        let result = store.store_fingerprint(
            user_id,
            fingerprint_hash,
            None,
            None,
            30,
        ).await;
        assert!(result.is_ok());

        // Manually expire the fingerprint by setting past expiration
        if let Some(mut fp) = store.fingerprints.get_mut(fingerprint_hash) {
            fp.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        }

        // Validate should now return false due to expiration
        let is_valid = store.validate_fingerprint(fingerprint_hash, user_id).await.unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_cleanup_expired_fingerprints() {
        let store = InMemoryFingerprintStore::new();
        let user_id = uuid::Uuid::new_v4();

        // Store multiple fingerprints
        for i in 0..5 {
            let fingerprint_hash = format!("test_hash_{}", i);
            store.store_fingerprint(
                user_id,
                &fingerprint_hash,
                None,
                None,
                30,
            ).await.unwrap();
        }

        // Manually expire some fingerprints
        for mut entry in store.fingerprints.iter_mut() {
            let hash = entry.key();
            if hash.contains("test_hash_1") || hash.contains("test_hash_3") {
                entry.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
            }
        }

        // Run cleanup
        let cleaned = store.cleanup_expired().await.unwrap();

        // Should have cleaned 2 expired fingerprints
        assert_eq!(cleaned, 2);

        // Check remaining fingerprints
        let remaining = store.fingerprints.len();
        assert_eq!(remaining, 3);
    }
}
