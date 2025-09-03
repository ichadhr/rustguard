use crate::response::api_response::ApiErrorResponse;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Invalid token")]
    InvalidToken(String),
    #[error("Token has expired")]
    TokenExpired,
    #[error("Missing Bearer token")]
    MissingToken,
    #[error("Token error: {0}")]
    TokenCreationError(String),
    #[error("Invalid fingerprint")]
    InvalidFingerprint,
    #[error("Missing fingerprint cookie")]
    MissingFingerprint,
    #[error("Invalid refresh token")]
    InvalidRefreshToken,
    #[error("Refresh token has expired")]
    RefreshTokenExpired,
    #[error("Missing refresh token")]
    MissingRefreshToken,
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let status_code = match self {
            TokenError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            TokenError::TokenExpired => StatusCode::UNAUTHORIZED,
            TokenError::MissingToken => StatusCode::UNAUTHORIZED,
            TokenError::TokenCreationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            TokenError::InvalidFingerprint => StatusCode::UNAUTHORIZED,
            TokenError::MissingFingerprint => StatusCode::UNAUTHORIZED,
            TokenError::InvalidRefreshToken => StatusCode::UNAUTHORIZED,
            TokenError::RefreshTokenExpired => StatusCode::UNAUTHORIZED,
            TokenError::MissingRefreshToken => StatusCode::UNAUTHORIZED,
        };

        ApiErrorResponse::send(status_code.as_u16(), Some(self.to_string()))
    }
}
