use crate::config::database::{Database, DatabaseTrait};
use crate::entity::user::User;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx;
use sqlx::Error;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct UserRepository {
    pub(crate) db_conn: Arc<Database>,
}

#[async_trait]
pub trait UserRepositoryTrait {
    fn new(db_conn: &Arc<Database>) -> Self;
    async fn find_by_email(&self, email: String) -> Option<User>;
    async fn find(&self, id: uuid::Uuid) -> Result<User, Error>;
    async fn store_refresh_token(
        &self,
        user_id: Uuid,
        refresh_token_hash: &str,
        family_id: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), Error>;
    async fn validate_refresh_token(&self, refresh_token_hash: &str, user_id: Uuid) -> Result<bool, Error>;
    async fn invalidate_refresh_token(&self, refresh_token_hash: &str, user_id: Uuid) -> Result<(), Error>;
    async fn invalidate_refresh_family(&self, family_id: &str, user_id: Uuid) -> Result<(), Error>;
    async fn find_by_refresh_token_hash(&self, refresh_token_hash: &str) -> Option<User>;
}

#[async_trait]
impl UserRepositoryTrait for UserRepository {
    fn new(db_conn: &Arc<Database>) -> Self {
        Self {
            db_conn: Arc::clone(db_conn),
        }
    }

    async fn find_by_email(&self, email: String) -> Option<User> {
        let start = std::time::Instant::now();

        match sqlx::query_as::<_, User>(
            "SELECT id, first_name, last_name, username, email, password, role, is_active, created_at, updated_at, refresh_token_hash, refresh_token_expires_at, refresh_token_family FROM users WHERE email = $1"
        )
        .bind(&email)
        .fetch_optional(self.db_conn.get_pool())
        .await {
            Ok(user) => {
                let duration = start.elapsed();
                info!("User lookup by email '{}' completed in {:?}", email, duration);
                user
            }
            Err(e) => {
                let duration = start.elapsed();
                warn!("User lookup by email '{}' failed after {:?}: {}", email, duration, e);
                None
            }
        }
    }

    async fn find(&self, id: uuid::Uuid) -> Result<User, Error> {
        let start = std::time::Instant::now();

        match sqlx::query_as::<_, User>(
            "SELECT id, first_name, last_name, username, email, password, role, is_active, created_at, updated_at, refresh_token_hash, refresh_token_expires_at, refresh_token_family FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_one(self.db_conn.get_pool())
        .await {
            Ok(user) => {
                let duration = start.elapsed();
                info!("User lookup by ID '{}' completed in {:?}", id, duration);
                Ok(user)
            }
            Err(e) => {
                let duration = start.elapsed();
                warn!("User lookup by ID '{}' failed after {:?}: {}", id, duration, e);
                Err(e)
            }
        }
    }

    async fn store_refresh_token(
        &self,
        user_id: Uuid,
        refresh_token_hash: &str,
        family_id: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), Error> {
        let start = std::time::Instant::now();

        match sqlx::query(
            "UPDATE users SET refresh_token_hash = $1, refresh_token_expires_at = $2, refresh_token_family = $3, updated_at = NOW() WHERE id = $4"
        )
        .bind(refresh_token_hash)
        .bind(expires_at)
        .bind(family_id)
        .bind(user_id)
        .execute(self.db_conn.get_pool())
        .await {
            Ok(_) => {
                let duration = start.elapsed();
                info!("Refresh token stored for user '{}' in {:?}", user_id, duration);
                Ok(())
            }
            Err(e) => {
                let duration = start.elapsed();
                warn!("Failed to store refresh token for user '{}' after {:?}: {}", user_id, duration, e);
                Err(e)
            }
        }
    }

    async fn validate_refresh_token(&self, refresh_token_hash: &str, user_id: Uuid) -> Result<bool, Error> {
        let start = std::time::Instant::now();

        match sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND refresh_token_hash = $2 AND refresh_token_expires_at > NOW())"
        )
        .bind(user_id)
        .bind(refresh_token_hash)
        .fetch_one(self.db_conn.get_pool())
        .await {
            Ok(exists) => {
                let duration = start.elapsed();
                info!("Refresh token validation for user '{}' completed in {:?}: {}", user_id, duration, exists);
                Ok(exists)
            }
            Err(e) => {
                let duration = start.elapsed();
                warn!("Refresh token validation failed for user '{}' after {:?}: {}", user_id, duration, e);
                Err(e)
            }
        }
    }

    async fn invalidate_refresh_token(&self, refresh_token_hash: &str, user_id: Uuid) -> Result<(), Error> {
        let start = std::time::Instant::now();

        match sqlx::query(
            "UPDATE users SET refresh_token_hash = NULL, refresh_token_expires_at = NULL, refresh_token_family = NULL, updated_at = NOW() WHERE id = $1 AND refresh_token_hash = $2"
        )
        .bind(user_id)
        .bind(refresh_token_hash)
        .execute(self.db_conn.get_pool())
        .await {
            Ok(_) => {
                let duration = start.elapsed();
                info!("Refresh token invalidated for user '{}' in {:?}", user_id, duration);
                Ok(())
            }
            Err(e) => {
                let duration = start.elapsed();
                warn!("Failed to invalidate refresh token for user '{}' after {:?}: {}", user_id, duration, e);
                Err(e)
            }
        }
    }

    async fn invalidate_refresh_family(&self, family_id: &str, user_id: Uuid) -> Result<(), Error> {
        let start = std::time::Instant::now();

        match sqlx::query(
            "UPDATE users SET refresh_token_hash = NULL, refresh_token_expires_at = NULL, refresh_token_family = NULL, updated_at = NOW() WHERE id = $1 AND refresh_token_family = $2"
        )
        .bind(user_id)
        .bind(family_id)
        .execute(self.db_conn.get_pool())
        .await {
            Ok(_) => {
                let duration = start.elapsed();
                info!("Refresh token family '{}' invalidated for user '{}' in {:?}", family_id, user_id, duration);
                Ok(())
            }
            Err(e) => {
                let duration = start.elapsed();
                warn!("Failed to invalidate refresh token family '{}' for user '{}' after {:?}: {}", family_id, user_id, duration, e);
                Err(e)
            }
        }
    }

    async fn find_by_refresh_token_hash(&self, refresh_token_hash: &str) -> Option<User> {
        let start = std::time::Instant::now();

        match sqlx::query_as::<_, User>(
            "SELECT id, first_name, last_name, username, email, password, role, is_active, created_at, updated_at, refresh_token_hash, refresh_token_expires_at, refresh_token_family FROM users WHERE refresh_token_hash = $1 AND refresh_token_expires_at > NOW()"
        )
        .bind(refresh_token_hash)
        .fetch_optional(self.db_conn.get_pool())
        .await {
            Ok(user) => {
                let duration = start.elapsed();
                if user.is_some() {
                    info!("User found by refresh token hash in {:?}", duration);
                } else {
                    info!("No user found with refresh token hash in {:?}", duration);
                }
                user
            }
            Err(e) => {
                let duration = start.elapsed();
                warn!("Error finding user by refresh token hash after {:?}: {}", duration, e);
                None
            }
        }
    }
}
