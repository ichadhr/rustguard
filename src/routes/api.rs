use crate::handler::api_handler;
use axum::{routing::get, Router};

pub fn routes() -> Router {
    Router::new()
        .route("/", get(api_handler::api_info))
        .route("/{*path}", get(api_handler::not_found))
}