use crate::config::database::{Database, DatabaseTrait};
use crate::config::logging::secure_log;
use crate::dto::user_dto::{UserReadDto, UserRegisterDto};
use crate::entity::user::User;
use crate::error::{AppError, db_error::DbError, user_error::UserError};
use crate::repository::user_repository::{UserRepository, UserRepositoryTrait};
use std::sync::Arc;
use tracing::info;

#[derive(Clone)]
pub struct UserService {
    user_repo: UserRepository,
    db_conn: Arc<Database>,
}

impl UserService {
    pub fn new(db_conn: &Arc<Database>) -> Self {
        Self {
            user_repo: UserRepository::new(db_conn),
            db_conn: Arc::clone(db_conn),
        }
    }

    pub async fn create_user(&self, payload: UserRegisterDto) -> Result<UserReadDto, AppError> {
        // Validate password strength before proceeding
        self.validate_password_strength(&payload.password)?;

        // Check if user already exists
        match self.user_repo.email_exists(payload.email.to_owned()).await {
            Ok(exists) => {
                if exists {
                    return Err(UserError::UserAlreadyExists)?;
                }
            }
            Err(e) => {
                secure_log::secure_error!("Failed to check email existence", e);
                return Err(AppError::Db(DbError::SomethingWentWrong("Failed to validate email".to_string())));
            }
        }

        // Check if username already exists
        match self.user_repo.username_exists(payload.username.to_owned()).await {
            Ok(exists) => {
                if exists {
                    return Err(UserError::UserAlreadyExists)?;
                }
            }
            Err(e) => {
                secure_log::secure_error!("Failed to check username existence", e);
                return Err(AppError::Db(DbError::SomethingWentWrong("Failed to validate username".to_string())));
            }
        }

        // Create new user
        match self.add_user(payload).await {
            Ok(user) => Ok(UserReadDto::from(user)),
            Err(e) => {
                secure_log::secure_error!("Failed to create user", e);
                Err(AppError::Db(DbError::SomethingWentWrong("User creation failed".to_string())))
            }
        }
    }

    async fn add_user(&self, payload: UserRegisterDto) -> Result<User, AppError> {
        let user_id = uuid::Uuid::now_v7();

        // Hash password with configurable cost factor for better security
        let bcrypt_cost = crate::config::parameter::get_u64_or_panic("BCRYPT_COST") as u32;
        let hashed_password = bcrypt::hash(payload.password, bcrypt_cost)
            .map_err(|e| {
                secure_log::secure_error!("Failed to hash password", e);
                secure_log::sensitive_debug!("Password hashing cost: {}", bcrypt_cost);
                AppError::Db(DbError::SomethingWentWrong("Password hashing failed".to_string()))
            })?;

        let insert_result = sqlx::query_as!(
            User,
            r#"
        INSERT INTO users (id, first_name, last_name, username, email, password, role, is_active)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
            user_id,
            payload.first_name.as_deref().unwrap_or(""),
            payload.last_name.as_deref().unwrap_or(""),
            payload.username,
            payload.email,
            hashed_password,
            payload.role.as_deref().unwrap_or("user"),
            true
        )
        .execute(self.db_conn.get_pool())
        .await;

        match insert_result {
            Ok(_) => {
                match self.user_repo.find(user_id).await {
                    Ok(user) => Ok(user),
                    Err(e) => {
                        secure_log::secure_error!("Failed to find user after insertion", e);
                        Err(AppError::Db(DbError::SomethingWentWrong("User creation failed".to_string())))
                    }
                }
            }
            Err(e) => {
                secure_log::secure_error!("Failed to insert user", e);
                Err(AppError::Db(DbError::SomethingWentWrong("User creation failed".to_string())))
            }
        }
    }

    pub async fn verify_password(&self, user: &User, password: &str) -> Result<bool, AppError> {
        // Use constant-time comparison to prevent timing attacks
        // bcrypt::verify already provides constant-time comparison, but we ensure
        // consistent response times regardless of password length or complexity
        let start_time = std::time::Instant::now();

        let result = bcrypt::verify(password, &user.password);

        // Ensure minimum processing time to prevent timing attacks
        let elapsed = start_time.elapsed();

        // Adaptive timing attack protection based on bcrypt cost
        let bcrypt_cost = crate::config::parameter::get_u64_or_panic("BCRYPT_COST") as u32;
        let adaptive_delay_ms = 25 + (bcrypt_cost * 5); // Base 25ms + 5ms per cost level
        let min_time = std::time::Duration::from_millis(adaptive_delay_ms as u64);

        if elapsed < min_time {
            tokio::time::sleep(min_time - elapsed).await;
        }

        match result {
            Ok(is_valid) => {
                // Log security events without exposing sensitive information
                if !is_valid {
                    secure_log::secure_error!("SECURITY: Invalid password attempt for user ID: {}", user.id);
                } else {
                    info!("SECURITY: Successful authentication for user ID: {} (email: {})", user.id, user.email);
                }
                Ok(is_valid)
            }
            Err(e) => {
                // Log error without exposing user details
                secure_log::secure_error!("SECURITY: Password verification system error", e);
                // Return false instead of error to prevent user enumeration
                Ok(false)
            }
        }
    }

    /// Validate password strength according to security policies
    /// OPTIMIZED: Single pass through string instead of 5 separate iterations
    fn validate_password_strength(&self, password: &str) -> Result<(), AppError> {
        let mut issues = Vec::new();

        // Length checks (no iteration needed)
        if password.len() < 8 {
            issues.push("at least 8 characters".to_string());
        }
        if password.len() > 128 {
            issues.push("no more than 128 characters".to_string());
        }

        // Single pass through string for all character checks
        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;
        let mut has_special = false;
        let mut consecutive_count = 1;
        let mut last_char = None;

        let special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

        for ch in password.chars() {
            // Character type checks (all in one pass)
            if ch.is_uppercase() { has_upper = true; }
            if ch.is_lowercase() { has_lower = true; }
            if ch.is_numeric() { has_digit = true; }
            if special_chars.contains(ch) { has_special = true; }

            // Consecutive character check (also in same pass)
            if let Some(last) = last_char {
                if ch == last {
                    consecutive_count += 1;
                    if consecutive_count > 3 {
                        issues.push("no more than 3 consecutive identical characters".to_string());
                        break; // Early exit on first violation
                    }
                } else {
                    consecutive_count = 1;
                }
            }
            last_char = Some(ch);
        }

        // Add issues for missing character types
        if !has_upper {
            issues.push("at least one uppercase letter (A-Z)".to_string());
        }
        if !has_lower {
            issues.push("at least one lowercase letter (a-z)".to_string());
        }
        if !has_digit {
            issues.push("at least one number (0-9)".to_string());
        }
        if !has_special {
            issues.push("at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)".to_string());
        }

        // If there are validation issues, return detailed error
        if !issues.is_empty() {
            let details = format!("Password must contain: {}", issues.join(", "));
            return Err(AppError::User(UserError::InvalidPasswordWithDetails { details }));
        }

        Ok(())
    }

    pub async fn find_by_id(&self, id: uuid::Uuid) -> Result<User, AppError> {
        self.user_repo.find(id).await.map_err(|e| {
            if let sqlx::Error::RowNotFound = e {
                AppError::User(UserError::UserNotFound)
            } else {
                secure_log::secure_error!("Failed to find user by ID", e);
                AppError::Db(DbError::SomethingWentWrong("Failed to find user".to_string()))
            }
        })
    }

    pub async fn get_users_paginated(
        &self,
        page_index: i32,
        page_size: i32,
        sort_field: Option<String>,
        sort_direction: Option<String>,
        global_filter: Option<String>,
    ) -> Result<(Vec<User>, i32), AppError> {
        self.user_repo
            .find_users_paginated(page_index, page_size, sort_field, sort_direction, global_filter)
            .await
            .map_err(|e| {
                secure_log::secure_error!("Failed to get paginated users", e);
                AppError::Db(DbError::SomethingWentWrong("Failed to retrieve users".to_string()))
            })
    }
}

