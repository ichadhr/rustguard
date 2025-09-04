use async_graphql::Error;
use crate::error::api_error::ApiError;
use crate::error::user_error::UserError;

pub fn map_api_error_to_graphql(error: ApiError, _field_path: Option<&str>) -> Error {
    // Simplified error mapping for now - can be enhanced later with extensions
    match error {
        ApiError::User(UserError::UserNotFound) => Error::new("User not found"),
        ApiError::User(UserError::InvalidPassword) => Error::new("Invalid password"),
        ApiError::User(UserError::InvalidPasswordWithDetails { details }) => Error::new(details),
        ApiError::User(UserError::UserAlreadyExists) => Error::new("User already exists"),
        ApiError::Token(_) => Error::new("Authentication required"),
        ApiError::Authorization(_) => Error::new("Insufficient permissions"),
        ApiError::Db(_) => Error::new("Database error"),
        ApiError::Fingerprint(_) => Error::new("Security error"),
    }
}