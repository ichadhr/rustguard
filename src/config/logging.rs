use crate::config::parameter;
use tracing::Level;

/// Environment types for log level configuration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Environment {
    Development,
    Production,
    Test,
}

impl Environment {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "production" | "prod" => Environment::Production,
            "test" | "testing" => Environment::Test,
            _ => Environment::Development,
        }
    }
}

/// Logging configuration for security-aware logging
#[derive(Debug)]
pub struct LoggingConfig {
    environment: Environment,
    log_level: Level,
}

impl LoggingConfig {
    /// Initialize logging configuration from environment variables
    pub fn init() -> Self {
        let environment = parameter::get_optional("ENV")
            .map(|s| Environment::from_str(&s))
            .unwrap_or(Environment::Development);

        let log_level = parameter::get_optional("LOG_LEVEL")
            .and_then(|level| match level.to_lowercase().as_str() {
                "error" => Some(Level::ERROR),
                "warn" => Some(Level::WARN),
                "info" => Some(Level::INFO),
                "debug" => Some(Level::DEBUG),
                "trace" => Some(Level::TRACE),
                _ => None,
            })
            .unwrap_or(Level::INFO);

        let config = Self {
            environment,
            log_level,
        };

        // Use direct tracing for internal config logging to avoid circular dependency
        tracing::info!("Logging configured: environment={:?}, level={:?}", config.environment, config.log_level);
        config
    }

    /// Check if detailed error logging is allowed
    pub fn allow_detailed_errors(&self) -> bool {
        matches!(self.environment, Environment::Development) || self.log_level >= Level::DEBUG
    }

    /// Check if sensitive data logging is allowed
    pub fn allow_sensitive_data(&self) -> bool {
        matches!(self.environment, Environment::Development) && self.log_level >= Level::DEBUG
    }

}

/// Global logging configuration instance
static LOGGING_CONFIG: std::sync::OnceLock<LoggingConfig> = std::sync::OnceLock::new();

/// Initialize global logging configuration
pub fn init() {
    if LOGGING_CONFIG.set(LoggingConfig::init()).is_err() {
        tracing::warn!("Logging configuration already initialized, skipping re-initialization");
    }
}

/// Get global logging configuration
pub fn get_config() -> &'static LoggingConfig {
    LOGGING_CONFIG.get().expect("Logging configuration not initialized")
}

/// Security-aware logging macros
pub mod secure_log {

    /// Log errors with environment-aware detail level
    macro_rules! secure_error {
        ($message:expr) => {
            if $crate::config::logging::get_config().allow_detailed_errors() {
                tracing::error!("{}", $message);
            } else {
                tracing::error!("An internal error occurred");
            }
        };
        ($message:expr, $error:expr) => {
            if $crate::config::logging::get_config().allow_detailed_errors() {
                tracing::error!("{}: {}", $message, $error);
            } else {
                tracing::error!("{}: An internal error occurred", $message);
            }
        };
        ($($arg:tt)*) => {
            if $crate::config::logging::get_config().allow_detailed_errors() {
                tracing::error!($($arg)*);
            } else {
                tracing::error!("An internal error occurred");
            }
        };
    }

    /// Log sensitive data only in development with debug level
    macro_rules! sensitive_debug {
        ($($arg:tt)*) => {
            if $crate::config::logging::get_config().allow_sensitive_data() {
                tracing::debug!($($arg)*);
            }
        };
    }

    pub(crate) use secure_error;
    pub(crate) use sensitive_debug;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_parsing() {
        assert!(matches!(Environment::from_str("development"), Environment::Development));
        assert!(matches!(Environment::from_str("prod"), Environment::Production));
        assert!(matches!(Environment::from_str("test"), Environment::Test));
        assert!(matches!(Environment::from_str("unknown"), Environment::Development));
    }

    #[test]
    fn test_logging_config_defaults() {
        // Test that config initializes with defaults when env vars are not set
        let config = LoggingConfig {
            environment: Environment::Development,
            log_level: Level::INFO,
        };

        assert!(config.allow_detailed_errors());
        assert!(!config.allow_sensitive_data()); // INFO level doesn't allow sensitive data
    }

    #[test]
    fn test_production_restrictions() {
        let config = LoggingConfig {
            environment: Environment::Production,
            log_level: Level::INFO,
        };

        assert!(!config.allow_detailed_errors());
        assert!(!config.allow_sensitive_data());
    }
}