use axum::{routing::get, Router};
use crate::handler::system_handler::{system_status, system_check, system_update};

pub fn routes() -> Router<()> {
    Router::new()
        .route("/", get(system_status))
        .route("/check", get(system_check))
        .route("/update", get(system_update))
}