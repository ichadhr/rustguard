use crate::response::api_response::ApiErrorResponse;
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

        ApiErrorResponse::send(status_code.as_u16(), Some(self.to_string()))
    }
}