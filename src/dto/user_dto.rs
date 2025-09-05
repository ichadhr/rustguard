use crate::entity::user::User;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Clone, Serialize, Deserialize, Validate)]
pub struct UserLoginDto {
    #[validate(email(message = "Email format is invalid"))]
    #[validate(length(
        max = 254,
        message = "Email must not exceed 254 characters"
    ))]
    pub email: String,
    #[validate(length(
        min = 8,
        max = 128,
        message = "Password must be between 8 and 128 characters"
    ))]
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize, Validate)]
pub struct UserRegisterDto {
    #[validate(email(message = "Email format is invalid"))]
    #[validate(length(
        max = 254,
        message = "Email must not exceed 254 characters"
    ))]
    pub email: String,
    #[validate(length(
        min = 8,
        max = 128,
        message = "Password must be between 8 and 128 characters"
    ))]
    pub password: String,
    #[validate(length(
        max = 100,
        message = "First name must not exceed 100 characters"
    ))]
    pub first_name: Option<String>,
    #[validate(length(
        max = 100,
        message = "Last name must not exceed 100 characters"
    ))]
    pub last_name: Option<String>,
    #[validate(length(
        min = 3,
        max = 30,
        message = "Username must be between 3 and 30 characters"
    ))]
    pub username: String,
    #[validate(length(
        max = 50,
        message = "Role must not exceed 50 characters"
    ))]
    pub role: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserReadDto {
    pub id: Uuid,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub username: String,
    pub email: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserReadDto {
    pub fn from(model: User) -> UserReadDto {
        Self {
            id: model.id,
            first_name: Some(model.first_name),
            last_name: Some(model.last_name),
            username: model.username,
            email: model.email,
            role: model.role,
            is_active: model.is_active,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl std::fmt::Debug for UserLoginDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("email", &self.email)
            .finish()
    }
}

impl std::fmt::Debug for UserRegisterDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("role", &self.role)
            .finish()
    }
}