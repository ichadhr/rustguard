use crate::response::app_response::ErrorResponse;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("User not found")]
    UserNotFound,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Password validation failed: {details}")]
    InvalidPasswordWithDetails { details: String },
}

impl IntoResponse for UserError {
    fn into_response(self) -> Response {
        let status_code = match self {
            UserError::UserNotFound => StatusCode::NOT_FOUND,
            UserError::UserAlreadyExists => StatusCode::BAD_REQUEST,
            UserError::InvalidPassword => StatusCode::BAD_REQUEST,
            UserError::InvalidPasswordWithDetails { .. } => StatusCode::BAD_REQUEST,
        };

        ErrorResponse::send(self.to_string()).with_status(status_code).into_response()
    }
}
