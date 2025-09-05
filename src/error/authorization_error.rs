use crate::response::app_response::ErrorResponse;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthorizationError {
    #[error("Access denied: {message}")]
    AccessDenied { message: String },
    #[error("Policy evaluation failed: {reason}")]
    PolicyEvaluationFailed { reason: String },
}

impl IntoResponse for AuthorizationError {
    fn into_response(self) -> Response {
        let status_code = match self {
            AuthorizationError::AccessDenied { .. } => StatusCode::FORBIDDEN,
            AuthorizationError::PolicyEvaluationFailed { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        };

        ErrorResponse::send(self.to_string()).with_status(status_code)
    }
}