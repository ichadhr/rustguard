use crate::handler::health_handler;
use axum::{routing::get, Router};
use std::sync::Arc;
use crate::config::database::Database;

pub fn routes() -> Router<Arc<Database>> {
    Router::new()
        .route("/health", get(health_handler::health_check))
        .route("/health/detail", get(health_handler::detailed_health_check))
}