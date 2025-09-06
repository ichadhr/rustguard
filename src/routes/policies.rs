use axum::{routing::post, Router};
use crate::handler::policy_handler;

pub fn routes() -> Router<()> {
    Router::new()
        .route("/", post(policy_handler::add_policy))
}