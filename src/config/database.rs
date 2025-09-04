use crate::config::parameter;
use async_trait::async_trait;
use sqlx::{Error, Pool, Postgres, pool::PoolOptions};
use tracing::info;

pub struct Database {
    pool: Pool<Postgres>,
}

#[async_trait]
pub trait DatabaseTrait {
    async fn init() -> Result<Self, Error>
        where
            Self: Sized;
    fn get_pool(&self) -> &Pool<Postgres>;
}

#[async_trait]
impl DatabaseTrait for Database {
    async fn init() -> Result<Self, Error> {
        let database_url = parameter::get_or_panic("DATABASE_URL");

        // Configure connection pool for optimal performance
        let max_connections = parameter::get_optional("DB_MAX_CONNECTIONS")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(20); // Default to 20 connections

        let min_connections = parameter::get_optional("DB_MIN_CONNECTIONS")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(5); // Default to 5 connections

        let acquire_timeout_seconds = parameter::get_optional("DB_ACQUIRE_TIMEOUT_SECONDS")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30); // Default to 30 seconds

        let idle_timeout_seconds = parameter::get_optional("DB_IDLE_TIMEOUT_SECONDS")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600); // Default to 10 minutes

        let max_lifetime_seconds = parameter::get_optional("DB_MAX_LIFETIME_SECONDS")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1800); // Default to 30 minutes

        let pool = PoolOptions::<Postgres>::new()
            .max_connections(max_connections)
            .min_connections(min_connections)
            .acquire_timeout(std::time::Duration::from_secs(acquire_timeout_seconds))
            .idle_timeout(std::time::Duration::from_secs(idle_timeout_seconds))
            .max_lifetime(std::time::Duration::from_secs(max_lifetime_seconds))
            .connect(&database_url)
            .await?;

        // Log database configuration securely - avoid exposing sensitive capacity information in production
        let is_development = cfg!(debug_assertions) ||
            parameter::get_optional("ENV")
                .map(|env| env == "development")
                .unwrap_or(false);
        if is_development {
            info!(
                "Database pool configured: max={}, min={}, acquire_timeout={}s, idle_timeout={}s, max_lifetime={}s",
                max_connections, min_connections, acquire_timeout_seconds, idle_timeout_seconds, max_lifetime_seconds
            );
        } else {
            info!("Database pool configured successfully");
        }

        Ok(Self { pool })
    }


    fn get_pool(&self) -> &Pool<Postgres> {
        &self.pool
    }
}
