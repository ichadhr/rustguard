use crate::config::database::{Database, DatabaseTrait};
use crate::config::logging::secure_log;
use crate::entity::user::User;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx;
use sqlx::Error;
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct UserRepository {
    pub(crate) db_conn: Arc<Database>,
}

#[async_trait]
pub trait UserRepositoryTrait {
    fn new(db_conn: &Arc<Database>) -> Self;
    async fn find_by_email(&self, email: String) -> Option<User>;
    async fn find_by_username(&self, username: String) -> Option<User>;
    async fn email_exists(&self, email: String) -> Result<bool, Error>;
    async fn username_exists(&self, username: String) -> Result<bool, Error>;
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
    async fn find_users_paginated(
        &self,
        page_index: i32,
        page_size: i32,
        sort_field: Option<String>,
        sort_direction: Option<String>,
        global_filter: Option<String>,
    ) -> Result<(Vec<User>, i32), Error>;
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
                let _duration = start.elapsed();
                secure_log::sensitive_debug!("User lookup by email completed in {:?}", _duration);
                user
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("User lookup by email failed", e);
                None
            }
        }
    }

    async fn find_by_username(&self, username: String) -> Option<User> {
        let start = std::time::Instant::now();

        match sqlx::query_as::<_, User>(
            "SELECT id, first_name, last_name, username, email, password, role, is_active, created_at, updated_at, refresh_token_hash, refresh_token_expires_at, refresh_token_family FROM users WHERE username = $1"
        )
        .bind(&username)
        .fetch_optional(self.db_conn.get_pool())
        .await {
            Ok(user) => {
                let _duration = start.elapsed();
                secure_log::sensitive_debug!("User lookup by username completed in {:?}", _duration);
                user
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("User lookup by username failed", e);
                None
            }
        }
    }

    async fn email_exists(&self, email: String) -> Result<bool, Error> {
        let start = std::time::Instant::now();

        match sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)"
        )
        .bind(&email)
        .fetch_one(self.db_conn.get_pool())
        .await {
            Ok(exists) => {
                let _duration = start.elapsed();
                secure_log::sensitive_debug!("Email existence check completed in {:?}", _duration);
                Ok(exists)
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("Email existence check failed", e);
                Err(e)
            }
        }
    }

    async fn username_exists(&self, username: String) -> Result<bool, Error> {
        let start = std::time::Instant::now();

        match sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)"
        )
        .bind(&username)
        .fetch_one(self.db_conn.get_pool())
        .await {
            Ok(exists) => {
                let _duration = start.elapsed();
                secure_log::sensitive_debug!("Username existence check completed in {:?}", _duration);
                Ok(exists)
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("Username existence check failed", e);
                Err(e)
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
                let _duration = start.elapsed();
                secure_log::sensitive_debug!("User lookup by ID completed in {:?}", _duration);
                Ok(user)
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("User lookup by ID failed", e);
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
                let _duration = start.elapsed();
                secure_log::sensitive_debug!("Refresh token stored for user in {:?}", _duration);
                Ok(())
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("Failed to store refresh token for user", e);
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
                let _duration = start.elapsed();
                secure_log::sensitive_debug!("Refresh token validation completed in {:?}", _duration);
                Ok(exists)
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("Refresh token validation failed", e);
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
                let _duration = start.elapsed();
                secure_log::sensitive_debug!("Refresh token invalidated for user in {:?}", _duration);
                Ok(())
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("Failed to invalidate refresh token for user", e);
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
                let _duration = start.elapsed();
                secure_log::sensitive_debug!("Refresh token family invalidated for user in {:?}", _duration);
                Ok(())
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("Failed to invalidate refresh token family", e);
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
                let _duration = start.elapsed();
                if user.is_some() {
                    info!("User found by refresh token hash in {:?}", _duration);
                } else {
                    info!("No user found with refresh token hash in {:?}", _duration);
                }
                user
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("Error finding user by refresh token hash", e);
                None
            }
        }
    }

    async fn find_users_paginated(
        &self,
        page_index: i32,
        page_size: i32,
        sort_field: Option<String>,
        sort_direction: Option<String>,
        global_filter: Option<String>,
    ) -> Result<(Vec<User>, i32), Error> {
        let start = std::time::Instant::now();
        let offset = page_index * page_size;

        // Build dynamic query based on parameters
        let mut query = r#"
            SELECT id, first_name, last_name, username, email, password, role, is_active, created_at, updated_at
            FROM users
        "#.to_string();

        let mut count_query = "SELECT COUNT(*) FROM users".to_string();
        let mut conditions = Vec::new();
        let mut bind_values = Vec::new();
        let mut param_count = 1;

        // Add global filter if provided
        if let Some(filter) = global_filter {
            let filter_condition = format!(
                "(username ILIKE ${} OR email ILIKE ${} OR first_name ILIKE ${} OR last_name ILIKE ${})",
                param_count, param_count + 1, param_count + 2, param_count + 3
            );
            let like_pattern = format!("%{}%", filter);
            conditions.push(filter_condition);
            bind_values.extend(vec![like_pattern.clone(), like_pattern.clone(), like_pattern.clone(), like_pattern]);
            param_count += 4;
        }

        // Add WHERE clause if we have conditions
        if !conditions.is_empty() {
            let where_clause = format!(" WHERE {}", conditions.join(" AND "));
            query.push_str(&where_clause);
            count_query.push_str(&where_clause);
        }

        // Add sorting
        let sort_field = sort_field.unwrap_or_else(|| "created_at".to_string());
        let sort_direction = sort_direction.unwrap_or_else(|| "DESC".to_string());
        let valid_sort_fields = vec!["username", "email", "created_at", "updated_at"];
        let sort_field = if valid_sort_fields.contains(&sort_field.as_str()) {
            sort_field
        } else {
            "created_at".to_string()
        };
        query.push_str(&format!(" ORDER BY {} {}", sort_field, sort_direction));

        // Add pagination
        query.push_str(&format!(" LIMIT ${} OFFSET ${}", param_count, param_count + 1));

        // Execute count query
        let count_result: Result<i64, Error> = if !conditions.is_empty() {
            let mut query_builder = sqlx::query_scalar(&count_query);
            for value in &bind_values {
                query_builder = query_builder.bind(value);
            }
            query_builder.fetch_one(self.db_conn.get_pool()).await
        } else {
            sqlx::query_scalar(&count_query)
                .fetch_one(self.db_conn.get_pool())
                .await
        };

        let total_count = match count_result {
            Ok(count) => count as i32,
            Err(e) => {
                secure_log::secure_error!("Failed to count users", e);
                return Err(e);
            }
        };

        // Execute main query
        let users_result: Result<Vec<User>, Error> = {
            let mut sql_query = sqlx::query_as::<_, User>(&query);
            // Bind filter values
            for value in &bind_values {
                sql_query = sql_query.bind(value);
            }
            // Bind pagination values
            sql_query = sql_query.bind(page_size);
            sql_query = sql_query.bind(offset);
            sql_query.fetch_all(self.db_conn.get_pool()).await
        };

        let users = match users_result {
            Ok(users) => {
                let _duration = start.elapsed();
                info!("Users paginated query completed in {:?}", _duration);
                users
            }
            Err(e) => {
                let _duration = start.elapsed();
                secure_log::secure_error!("Users paginated query failed", e);
                return Err(e);
            }
        };

        Ok((users, total_count))
    }
}
