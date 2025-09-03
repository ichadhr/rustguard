use crate::handler::profile_handler;
use axum::{routing::get, Router};

pub fn routes() -> Router {
    Router::new().route("/profile", get(profile_handler::profile))
}
