use crate::response::app_response::{ErrorResponse, ValidationErrorDetail};
use axum::extract::{rejection::JsonRejection, FromRequest, Request};
use axum::{Json, response::{IntoResponse, Response}, http::StatusCode};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;
use validator::Validate;

#[derive(Debug, Error)]
pub enum RequestError {
    #[error(transparent)]
    ValidationError(#[from] validator::ValidationErrors),
    #[error(transparent)]
    JsonRejection(#[from] JsonRejection),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedRequest<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedRequest<T>
where
    T: DeserializeOwned + Validate + Send,
    S: Send + Sync,
{
    type Rejection = RequestError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await
            .map_err(RequestError::JsonRejection)?;
        value.validate()?;
        Ok(ValidatedRequest(value))
    }
}

impl IntoResponse for RequestError {
    fn into_response(self) -> Response {
        match self {
            RequestError::ValidationError(validation_errors) => {
                let details = convert_validation_errors_to_details(validation_errors);
                ErrorResponse::with_validation_errors(
                    "Validation failed".to_string(),
                    details
                ).with_status(StatusCode::BAD_REQUEST).into_response()
            }
            RequestError::JsonRejection(_) => ErrorResponse::send(self.to_string()).with_status(StatusCode::BAD_REQUEST).into_response(),
        }
    }
}

fn convert_validation_errors_to_details(errors: validator::ValidationErrors) -> Vec<ValidationErrorDetail> {
    errors.field_errors()
        .into_iter()
        .flat_map(|(field, field_errors)| {
            field_errors.iter().map(move |error| {
                // Convert params HashMap to the expected type
                let params_string_keys: HashMap<String, Value> = error.params
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect();

                let semantic_type = map_validator_code_to_semantic_type(
                    &error.code.to_string(),
                    &params_string_keys
                );

                ValidationErrorDetail::new(
                    field.to_string(),
                    semantic_type,
                    error.message.clone()
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| "Invalid value".to_string())
                )
            })
        })
        .collect()
}

fn map_validator_code_to_semantic_type(code: &str, params: &HashMap<String, Value>) -> String {
    match code {
        "email" => "INVALID_FORMAT".to_string(),
        "length" => {
            if let Some(min) = params.get("min").and_then(|v| v.as_i64()) {
                if min == 1 && params.get("max").is_none() {
                    "MISSING".to_string()  // For required fields using length(min=1)
                } else if params.get("max").is_some() {
                    "INVALID_LENGTH".to_string()
                } else {
                    "TOO_SHORT".to_string()
                }
            } else {
                "INVALID_LENGTH".to_string()
            }
        }
        "custom" => "INVALID_VALUE".to_string(),
        "required" => "MISSING".to_string(),
        "MISSING" => "MISSING".to_string(),
        "INVALID_CHOICE" => "INVALID_CHOICE".to_string(),
        _ => "INVALID_VALUE".to_string(),
    }
}