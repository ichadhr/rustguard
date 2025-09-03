use super::auth;
use crate::config::database::Database;
use crate::error::token_error::TokenError;
use crate::handler::health_handler;
use crate::middleware::auth as auth_middleware;
use crate::middleware::rate_limit::{rate_limit_auth, rate_limit_general, RateLimitState};
use crate::routes::{profile, register};
use crate::state::auth_state::AuthState;
use crate::state::token_state::TokenState;
use crate::state::user_state::UserState;
use axum::routing::get;
use axum::{middleware, Router};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

pub fn routes(db_conn: Arc<Database>, rate_limit_state: RateLimitState) -> Result<Router, TokenError> {
    let merged_router = {
        let auth_state = AuthState::new(&db_conn)?;
        let user_state = UserState::new(&db_conn);
        let token_state = TokenState::new(&db_conn)?;

        // Auth endpoints with stricter rate limiting
        let auth_routes = auth::routes()
            .layer(ServiceBuilder::new().layer(
                middleware::from_fn_with_state(rate_limit_state.clone(), rate_limit_auth),
            ))
            .with_state(auth_state);

        // Register endpoints with stricter rate limiting
        let register_routes = register::routes()
            .layer(ServiceBuilder::new().layer(
                middleware::from_fn_with_state(rate_limit_state.clone(), rate_limit_auth),
            ))
            .with_state(user_state);

        // Profile endpoints with general rate limiting + auth middleware
        let profile_routes = profile::routes()
            .layer(ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(rate_limit_state.clone(), rate_limit_general))
                .layer(middleware::from_fn_with_state(token_state, auth_middleware::auth))
            );

        // Health endpoints with general rate limiting
        let health_routes = Router::new()
            .route("/health", get(health_handler::health_check))
            .route("/health/detailed", get(health_handler::detailed_health_check))
            .layer(ServiceBuilder::new().layer(
                middleware::from_fn_with_state(rate_limit_state, rate_limit_general),
            ))
            .with_state(db_conn.clone());

        auth_routes
            .merge(register_routes)
            .merge(profile_routes)
            .merge(health_routes)
    };

    let app_router = Router::new()
        .nest("/api", merged_router)
        .layer(TraceLayer::new_for_http());

    Ok(app_router)
}
