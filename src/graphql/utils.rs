use async_graphql::Error;
use crate::error::AppError;
use crate::error::user_error::UserError;

pub fn map_api_error_to_graphql(error: AppError, _field_path: Option<&str>) -> Error {
    // Simplified error mapping for now - can be enhanced later with extensions
    match error {
        AppError::User(UserError::UserNotFound) => Error::new("User not found"),
        AppError::User(UserError::InvalidPassword) => Error::new("Invalid password"),
        AppError::User(UserError::InvalidPasswordWithDetails { details }) => Error::new(details),
        AppError::User(UserError::UserAlreadyExists) => Error::new("User already exists"),
        AppError::Token(_) => Error::new("Authentication required"),
        AppError::Authorization(_) => Error::new("Insufficient permissions"),
        AppError::Db(_) => Error::new("Database error"),
        AppError::Fingerprint(_) => Error::new("Security error"),
        AppError::Database(_) => Error::new("Database error"),
        AppError::Config(_) => Error::new("Configuration error"),
        AppError::Internal(_) => Error::new("Internal server error"),
        AppError::Request(_) => Error::new("Invalid request"),
    }
}