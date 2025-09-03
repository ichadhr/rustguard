use crate::error::db_error::DbError;
use crate::error::token_error::TokenError;
use crate::error::user_error::UserError;
use axum::response::{IntoResponse, Response};
use thiserror::Error;
use std::error::Error as StdError;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error(transparent)]
    User(#[from] UserError),
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("Fingerprint service error: {0}")]
    Fingerprint(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Token(error) => error.into_response(),
            ApiError::User(error) => error.into_response(),
            ApiError::Db(error) => error.into_response(),
            ApiError::Fingerprint(message) => {
                use axum::http::StatusCode;
                use axum::Json;
                use serde_json::json;
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                    "message": message,
                    "code": 500
                }))).into_response()
            }
        }
    }
}

impl From<Box<dyn StdError + Send + Sync>> for ApiError {
    fn from(error: Box<dyn StdError + Send + Sync>) -> Self {
        ApiError::Fingerprint(error.to_string())
    }
}
