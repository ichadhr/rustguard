use super::auth;
use crate::config::database::Database;
use crate::error::token_error::TokenError;
use crate::handler::health_handler;
use crate::middleware::auth as auth_middleware;
use crate::routes::{profile, register};
use crate::state::auth_state::AuthState;
use crate::state::token_state::TokenState;
use crate::state::user_state::UserState;
use axum::routing::get;
use axum::{middleware, Router};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

pub fn routes(db_conn: Arc<Database>) -> Result<Router, TokenError> {
    let merged_router = {
        let auth_state = AuthState::new(&db_conn)?;
        let user_state = UserState::new(&db_conn);
        let token_state = TokenState::new(&db_conn)?;

        auth::routes()
            .with_state(auth_state)
            .merge(register::routes().with_state(user_state))
            .merge(profile::routes().layer(ServiceBuilder::new().layer(
                middleware::from_fn_with_state(token_state, auth_middleware::auth),
            )))
            .merge(
                Router::new()
                    .route("/health", get(health_handler::health_check))
                    .route("/health/detailed", get(health_handler::detailed_health_check))
                    .with_state(db_conn.clone())
            )
    };

    let app_router = Router::new()
        .nest("/api", merged_router)
        .layer(TraceLayer::new_for_http());

    Ok(app_router)
}
