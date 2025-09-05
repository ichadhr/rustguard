use crate::response::app_response::ErrorResponse;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("{0}")]
    SomethingWentWrong(String)
}

impl IntoResponse for DbError {
    fn into_response(self) -> Response {
        let status_code = match self {
            DbError::SomethingWentWrong(_) => StatusCode::INTERNAL_SERVER_ERROR
        };

        ErrorResponse::send(self.to_string()).with_status(status_code)
    }
}
