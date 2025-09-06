use crate::config::database::Database;
use crate::error::AppError;
use crate::handler::health_handler;
use crate::middleware::auth as auth_middleware;
use crate::middleware::authorization;
use crate::middleware::rate_limit::{rate_limit_auth, rate_limit_general, RateLimitState};
use crate::routes::{profile, register, policies, permissions, auth, graphql, system};
use crate::service::fingerprint_service::FingerprintStore;
use crate::service::token_service::{TokenService, TokenServiceTrait};
use crate::state::auth_state::AuthState;
use crate::state::casbin_state::CasbinState;
use crate::state::token_state::TokenState;
use crate::state::user_state::UserState;
use crate::state::graphql_state::GraphQLState;
use axum::routing::get;
use axum::{middleware, Router};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

pub async fn routes(
    db_conn: Arc<Database>,
    rate_limit_state: RateLimitState,
    casbin_state: CasbinState,
    graphql_state: GraphQLState,
    fingerprint_store: Arc<dyn FingerprintStore>
) -> Result<Router, AppError> {
    let merged_router = {
        // Create shared token service to avoid duplicate initialization
        let shared_token_service = TokenService::new()?;
        let auth_state = AuthState::new_with_token_service_and_fingerprint_store(&db_conn, shared_token_service.clone(), fingerprint_store.clone())?;
        let user_state = UserState::new(&db_conn);
        let token_state = TokenState::new_with_token_service_and_fingerprint_store(&db_conn, shared_token_service.clone(), fingerprint_store.clone())?;

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

        // Profile endpoints with general rate limiting + auth middleware + authorization
        let profile_routes = profile::routes()
            .layer(ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(rate_limit_state.clone(), rate_limit_general))
                .layer(middleware::from_fn_with_state(token_state.clone(), auth_middleware::auth))
                .layer(middleware::from_fn_with_state(casbin_state.enforcer.clone(), authorization::authorize))
            )
            .layer(axum::extract::Extension(casbin_state.enforcer.clone()));

        // Policy endpoints with auth + authorization + rate limiting
        let policy_routes = policies::routes()
            .layer(ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(rate_limit_state.clone(), rate_limit_general))
                .layer(middleware::from_fn_with_state(token_state.clone(), auth_middleware::auth))
                .layer(middleware::from_fn_with_state(casbin_state.enforcer.clone(), authorization::authorize))
            )
            .layer(axum::extract::Extension(casbin_state.enforcer.clone()));

        // Permission endpoints with auth + authorization + rate limiting
        let permission_routes = permissions::routes()
            .layer(ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(rate_limit_state.clone(), rate_limit_general))
                .layer(middleware::from_fn_with_state(token_state.clone(), auth_middleware::auth))
                .layer(middleware::from_fn_with_state(casbin_state.enforcer.clone(), authorization::authorize))
            )
            .layer(axum::extract::Extension(casbin_state.enforcer.clone()));

        // System endpoints with auth + authorization + rate limiting
        let system_routes = system::routes()
            .layer(ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(rate_limit_state.clone(), rate_limit_general))
                .layer(middleware::from_fn_with_state(token_state.clone(), auth_middleware::auth))
                .layer(middleware::from_fn_with_state(casbin_state.enforcer.clone(), authorization::authorize))
            )
            .layer(axum::extract::Extension(casbin_state.enforcer.clone()));

        // GraphQL endpoints with auth + authorization + rate limiting
        let graphql_routes = graphql::routes()
            .layer(ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(rate_limit_state.clone(), rate_limit_general))
                .layer(middleware::from_fn_with_state(token_state.clone(), auth_middleware::auth))
                .layer(middleware::from_fn_with_state(casbin_state.enforcer.clone(), authorization::authorize))
            )
            .layer(axum::extract::Extension(casbin_state.enforcer.clone()))
            .with_state(graphql_state);

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
            .nest("/policies", policy_routes)
            .nest("/permissions", permission_routes)
            .nest("/system", system_routes)
            .merge(graphql_routes)
            .merge(health_routes)
    };

    let app_router = Router::new()
        .nest("/api", merged_router)
        .layer(TraceLayer::new_for_http());

    Ok(app_router)
}
