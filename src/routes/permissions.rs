use axum::{routing::post, Router};
use crate::handler::permission_handler;

pub fn routes() -> Router<()> {
    Router::new()
        .route("/check", post(permission_handler::check_permission))
}