use async_graphql::*;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::common::{Connection, PaginationInput, SortInput, GlobalFilter};

// ===== USER GRAPHQL TYPES =====
#[derive(SimpleObject)]
pub struct User {
    pub id: ID,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum UserRole {
    USER,
    ADMIN,
    MODERATOR,
}

// ===== FILTERS =====
#[derive(InputObject)]
pub struct UserFilter {
    pub global: Option<GlobalFilter>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub role: Option<UserRole>,
    pub is_active: Option<bool>,
    pub created_at: Option<DateRange>,
}

#[derive(InputObject)]
pub struct DateRange {
    pub start: Option<String>,
    pub end: Option<String>,
}

// ===== SORTING =====
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum UserSortField {
    USERNAME,
    EMAIL,
    CreatedAt,
    UpdatedAt,
}

#[derive(InputObject)]
pub struct UserSortInput {
    pub field: UserSortField,
    pub direction: super::common::SortDirection,
}

// ===== CONVERSIONS =====
impl From<crate::entity::user::User> for User {
    fn from(user: crate::entity::user::User) -> Self {
        Self {
            id: user.id.to_string().into(),
            username: user.username,
            email: user.email,
            first_name: user.first_name.into(),
            last_name: user.last_name.into(),
            role: match user.role.as_str() {
                "admin" => UserRole::ADMIN,
                "moderator" => UserRole::MODERATOR,
                _ => UserRole::USER,
            },
            is_active: user.is_active,
            created_at: user.created_at.to_rfc3339(),
            updated_at: user.updated_at.to_rfc3339(),
        }
    }
}

impl From<String> for UserRole {
    fn from(role: String) -> Self {
        match role.as_str() {
            "admin" => UserRole::ADMIN,
            "moderator" => UserRole::MODERATOR,
            _ => UserRole::USER,
        }
    }
}

// Type alias for cleaner code
pub type UserConnection = Connection<User>;