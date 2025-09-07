use crate::response::app_response::{ErrorResponse, ErrorDetail};
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

        let (message, error_type, details) = match self {
            AuthorizationError::AccessDenied { message } => (
                "Access denied".to_string(),
                "AUTHORIZATION_ERROR".to_string(),
                message,
            ),
            AuthorizationError::PolicyEvaluationFailed { reason } => (
                "Policy evaluation failed".to_string(),
                "POLICY_ERROR".to_string(),
                reason,
            ),
        };

        ErrorResponse::with_error_details(
            message,
            vec![ErrorDetail::new(error_type, details)]
        )
        .with_status(status_code)
        .into_response()
    }
}