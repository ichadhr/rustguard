use crate::response::api_response::ApiErrorResponse;
use axum::extract::{rejection::JsonRejection, FromRequest, Request};
use axum::{Json, response::{IntoResponse, Response}};
use serde::de::DeserializeOwned;
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
            RequestError::ValidationError(_) => {
                ApiErrorResponse::send(400, Some(self.to_string().replace('\n', ", ")))
            }
            RequestError::JsonRejection(_) => ApiErrorResponse::send(400, Some(self.to_string())),
        }
    }
}