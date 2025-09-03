use crate::handler::auth_handler;
use crate::handler::refresh_handler;
use crate::state::auth_state::AuthState;
use axum::{routing::post, Router};

pub fn routes() -> Router<AuthState> {
    Router::<AuthState>::new()
        .route("/auth", post(auth_handler::auth))
        .route("/refresh", post(refresh_handler::refresh_token))
        .route("/logout", post(refresh_handler::logout))
}
