use dotenv;
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{info, warn, error};

static CONFIG: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Default configuration values
const DEFAULTS: &[(&str, &str)] = &[
    ("SERVER_ADDRESS", "127.0.0.1"),
    ("SERVER_PORT", "8081"),
    ("JWT_TTL_IN_MINUTES", "30"),
    ("JWT_MAX_AGE_SECONDS", "1800"), // 30 minutes
    ("FINGERPRINT_COOKIE_MAX_AGE_DAYS", "30"),
    ("FINGERPRINT_CLEANUP_INTERVAL_MINUTES", "60"),
    ("BCRYPT_COST", "12"),
    ("MAX_REQUEST_SIZE_MB", "10"),
    ("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"),
    ("LOG_LEVEL", "info"),
    // Refresh token configuration
    ("REFRESH_TOKEN_TTL_DAYS", "30"),
    ("REFRESH_TOKEN_ROTATION", "true"),
    ("REFRESH_TOKEN_FAMILY_LOGOUT", "true"),
];

pub fn init() {
    match dotenv::dotenv() {
        Ok(path) => info!("Loaded environment file: {:?}", path),
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
        error!("Configuration already initialized");
    } else {
        info!("Configuration initialized successfully");
    }
}

pub fn get(parameter: &str) -> String {
    CONFIG
        .get()
        .and_then(|config| config.get(parameter))
        .cloned()
        .unwrap_or_else(|| {
            error!("Configuration parameter '{}' not found", parameter);
            panic!("Required configuration parameter '{}' is missing", parameter);
        })
}

pub fn get_optional(parameter: &str) -> Option<String> {
    CONFIG
        .get()
        .and_then(|config| config.get(parameter))
        .cloned()
}

pub fn get_i64(parameter: &str) -> i64 {
    let value = get(parameter);
    value.parse::<i64>().unwrap_or_else(|_| {
        error!("Configuration parameter '{}' is not a valid i64: {}", parameter, value);
        panic!("Configuration parameter '{}' is not a valid i64", parameter);
    })
}

#[allow(dead_code)]
pub fn get_bool(parameter: &str) -> bool {
    let value = get(parameter).to_lowercase();
    matches!(value.as_str(), "true" | "1" | "yes" | "on")
}

pub fn get_u64(parameter: &str) -> u64 {
    let value = get(parameter);
    value.parse::<u64>().unwrap_or_else(|_| {
        error!("Configuration parameter '{}' is not a valid u64: {}", parameter, value);
        panic!("Configuration parameter '{}' is not a valid u64", parameter);
    })
}

/// Get all configuration parameters (for debugging)
pub fn get_all() -> HashMap<String, String> {
    CONFIG.get().cloned().unwrap_or_default()
}
