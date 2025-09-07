pub(crate) mod authorization_error;
pub(crate) mod db_error;
pub(crate) mod request_error;
pub(crate) mod token_error;
pub(crate) mod user_error;

// Unified application error type
#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error(transparent)]
    Authorization(#[from] authorization_error::AuthorizationError),
    #[error(transparent)]
    Token(#[from] token_error::TokenError),
    #[error(transparent)]
    User(#[from] user_error::UserError),
    #[error(transparent)]
    Db(#[from] db_error::DbError),
    #[error(transparent)]
    Request(#[from] request_error::RequestError),
    #[error("Fingerprint service error: {0}")]
    Fingerprint(String),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Configuration error: {0}")]
    #[allow(dead_code)] // TODO
    Config(String),
    #[error("Internal error: {0}")]
    #[allow(dead_code)] // TODO
    Internal(String),
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use crate::response::app_response::ErrorResponse;

        let (status, message) = match &self {
            AppError::Authorization(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::Token(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::User(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Db(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()),
            AppError::Request(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Fingerprint(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Authentication error".to_string()),
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()),
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error".to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        ErrorResponse::send(message).with_status(status).into_response()
    }
}
