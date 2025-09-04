use axum::{routing::post, Router};
use crate::handler::admin_handler::{add_policy, check_permission};

pub fn routes() -> Router<()> {
    Router::new()
        .route("/policies", post(add_policy))
        .route("/permissions/check", post(check_permission))
}