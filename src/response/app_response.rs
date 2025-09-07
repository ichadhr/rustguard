use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

/// Detailed validation error information
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ValidationErrorDetail {
    pub field: String,
    pub r#type: String,
    pub details: String,
}

/// Detailed error information
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ErrorDetail {
    pub r#type: String,
    pub details: String,
}

impl ValidationErrorDetail {
    pub fn new(field: String, r#type: String, details: String) -> Self {
        Self { field, r#type, details }
    }
}

impl ErrorDetail {
    pub fn new(r#type: String, details: String) -> Self {
        Self { r#type, details }
    }
}

/// JSO (JSON Success Object) Success Response
/// Standard format for all successful REST API responses
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SuccessResponse<T> {
    pub success: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    #[serde(skip)]
    pub status_code: StatusCode,
}

impl<T> SuccessResponse<T> {
    /// Create a success response with default 200 OK status
    pub fn send(data: T) -> Self {
        Self {
            success: true,
            data,
            meta: None,
            status_code: StatusCode::OK,
        }
    }

    /// Set custom status code (builder pattern)
    pub fn with_status(mut self, status_code: StatusCode) -> Self {
        self.status_code = status_code;
        self
    }

    /// Set meta data (builder pattern)
    #[allow(dead_code)] // TODO
    pub fn with_meta(mut self, meta: serde_json::Value) -> Self {
        self.meta = Some(meta);
        self
    }
}

impl<T> IntoResponse for SuccessResponse<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        (self.status_code, Json(self)).into_response()
    }
}

/// JSO (JSON Success Object) Error Response
/// Standard format for all error REST API responses
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<ValidationErrorDetail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Vec<ErrorDetail>>,
    #[serde(skip)]
    pub status_code: StatusCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

impl ErrorResponse {
    /// Create an error response with default 400 Bad Request status
    pub fn send(message: String) -> Self {
        Self {
            success: false,
            message,
            errors: None,
            error: None,
            meta: None,
            status_code: StatusCode::BAD_REQUEST,
        }
    }

    /// Create an error response with validation errors
    pub fn with_validation_errors(message: String, errors: Vec<ValidationErrorDetail>) -> Self {
        Self {
            success: false,
            message,
            errors: Some(errors),
            error: None,
            meta: None,
            status_code: StatusCode::BAD_REQUEST,
        }
    }

    /// Create an error response with error details
    pub fn with_error_details(message: String, errors: Vec<ErrorDetail>) -> Self {
        Self {
            success: false,
            message,
            errors: None,
            error: Some(errors),
            meta: None,
            status_code: StatusCode::BAD_REQUEST,
        }
    }

    /// Set custom status code (builder pattern)
    pub fn with_status(mut self, status_code: StatusCode) -> Self {
        self.status_code = status_code;
        self
    }

    /// Set meta data (builder pattern)
    #[allow(dead_code)] // TODO
    pub fn with_meta(mut self, meta: serde_json::Value) -> Self {
        self.meta = Some(meta);
        self
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (self.status_code, Json(self)).into_response()
    }
}

