use dotenv;
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{info, warn};
use crate::config::logging::secure_log;

/// Configuration error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Configuration parameter '{0}' is missing")]
    MissingParameter(String),
    #[error("Configuration parameter '{0}' has invalid format: {1}")]
    InvalidFormat(String, String),
}

static CONFIG: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Default configuration values
const DEFAULTS: &[(&str, &str)] = &[
    ("APP_NAME", "RustGuard"),
    ("SERVER_ADDRESS", "127.0.0.1"),
    ("SERVER_PORT", "8081"),
    ("DATABASE_URL", ""),
    ("JWT_SECRET", ""),
    ("JWT_TTL_IN_MINUTES", "30"),
    ("JWT_MAX_AGE_SECONDS", "1800"), // 30 minutes
    ("FINGERPRINT_COOKIE_MAX_AGE_DAYS", "30"),
    ("FINGERPRINT_CLEANUP_INTERVAL_MINUTES", "60"),
    ("BCRYPT_COST", "12"),
    ("MAX_REQUEST_SIZE_MB", "10"),
    ("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"),
    ("LOG_LEVEL", "info"),
    // Database pool configuration
    ("DB_MAX_CONNECTIONS", "20"),
    ("DB_MIN_CONNECTIONS", "5"),
    ("DB_ACQUIRE_TIMEOUT_SECONDS", "30"),
    ("DB_IDLE_TIMEOUT_SECONDS", "600"),
    ("DB_MAX_LIFETIME_SECONDS", "1800"),
    // Refresh token configuration
    ("REFRESH_TOKEN_TTL_DAYS", "30"),
    ("REFRESH_TOKEN_ROTATION", "true"),
    ("REFRESH_TOKEN_FAMILY_LOGOUT", "true"),
];

pub fn init() {
    match dotenv::dotenv() {
        Ok(path) => secure_log::sensitive_debug!("Loaded environment file: {:?}", path),
        Err(_) => warn!("No .env file found, using system environment variables"),
    }

    let mut config = HashMap::new();

    // Load defaults first
    for (key, value) in DEFAULTS {
        config.insert(key.to_string(), value.to_string());
    }

    // Override with environment variables
    for (key, _) in DEFAULTS {
        if let Ok(value) = std::env::var(key) {
            config.insert(key.to_string(), value);
        }
    }

    if CONFIG.set(config).is_err() {
        secure_log::secure_error!("Configuration already initialized");
    } else {
        info!("Configuration initialized successfully");
    }
}

pub fn get(parameter: &str) -> Result<String, ConfigError> {
    CONFIG
        .get()
        .and_then(|config| config.get(parameter))
        .cloned()
        .ok_or_else(|| {
            secure_log::secure_error!("Configuration parameter not found", parameter);
            ConfigError::MissingParameter(parameter.to_string())
        })
}

/// Get a configuration parameter with panic on error (backward compatibility)
pub fn get_or_panic(parameter: &str) -> String {
    get(parameter).unwrap_or_else(|e| panic!("{}", e))
}

pub fn get_optional(parameter: &str) -> Option<String> {
    CONFIG
        .get()
        .and_then(|config| config.get(parameter))
        .cloned()
}

pub fn get_i64(parameter: &str) -> Result<i64, ConfigError> {
    let value = get(parameter)?;
    value.parse::<i64>().map_err(|_| {
        secure_log::secure_error!("Configuration parameter '{}' is not a valid i64: {}", parameter, value);
        ConfigError::InvalidFormat(parameter.to_string(), value)
    })
}

/// Get a configuration parameter as i64 with panic on error (backward compatibility)
pub fn get_i64_or_panic(parameter: &str) -> i64 {
    get_i64(parameter).unwrap_or_else(|e| panic!("{}", e))
}

pub fn get_bool(parameter: &str) -> bool {
    match get(parameter) {
        Ok(value) => matches!(value.to_lowercase().as_str(), "true" | "1" | "yes" | "on"),
        Err(_) => false, // Default to false if parameter is missing or invalid
    }
}

pub fn get_u64(parameter: &str) -> Result<u64, ConfigError> {
    let value = get(parameter)?;
    value.parse::<u64>().map_err(|_| {
        secure_log::secure_error!("Configuration parameter '{}' is not a valid u64: {}", parameter, value);
        ConfigError::InvalidFormat(parameter.to_string(), value)
    })
}

/// Get a configuration parameter as u64 with panic on error (backward compatibility)
pub fn get_u64_or_panic(parameter: &str) -> u64 {
    get_u64(parameter).unwrap_or_else(|e| panic!("{}", e))
}

/// Get all configuration parameters (for debugging)
pub fn get_all() -> HashMap<String, String> {
    CONFIG.get().cloned().unwrap_or_default()
}
