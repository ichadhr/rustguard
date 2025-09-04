use std::sync::Arc;
use crate::config::{database, logging::{secure_log, init}, parameter};
use crate::config::database::DatabaseTrait;
use crate::graphql::schema::{query::QueryRoot, mutation::MutationRoot};
use crate::handler::health_handler;
use crate::middleware::rate_limit::RateLimitState;
use crate::service::casbin_service::CasbinService;
use crate::service::fingerprint_service::InMemoryFingerprintStore;
use crate::state::casbin_state::CasbinState;
use crate::state::graphql_state::GraphQLState;
use crate::lib_bin::start_fingerprint_cleanup_task;
use tracing::info;

mod config;
mod routes;
mod dto;
mod error;
mod response;
mod entity;
mod repository;
mod state;
mod service;
mod middleware;
mod handler;
mod lib_bin;
mod graphql;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging configuration and tracing BEFORE parameter initialization
    // This is required because parameter::init() uses secure_log macros
    if let Err(e) = init() {
        eprintln!("Failed to initialize logging: {}", e);
        return Err(e);
    }

    info!("Starting Rust JWT Fingerprinting Framework...");

    // Initialize configuration
    parameter::init();
    info!("Configuration initialized");

    // Initialize health check start time
    health_handler::init_start_time();

    // Initialize database connection
    let connection = match database::Database::init().await {
        Ok(conn) => {
            info!("Database connection established successfully");
            conn
        }
        Err(e) => {
            secure_log::secure_error!("Failed to initialize database", e);
            return Err(Box::new(e) as Box<dyn std::error::Error>);
        }
    };

    // Get server configuration
    let server_address = parameter::get_or_panic("SERVER_ADDRESS");
    let server_port = parameter::get_or_panic("SERVER_PORT");
    let host = format!("{}:{}", server_address, server_port);
    info!("Server will bind to: {}", host);

    // Initialize shared fingerprint store for cleanup task
    let fingerprint_store = InMemoryFingerprintStore::new_shared();
    info!("Fingerprint store initialized");

    // Get cleanup interval from configuration
    let cleanup_interval_minutes = parameter::get_u64_or_panic("FINGERPRINT_CLEANUP_INTERVAL_MINUTES");
    info!("Fingerprint cleanup interval: {} minutes", cleanup_interval_minutes);

    // Create cancellation token for graceful shutdown
    let cleanup_shutdown_token = tokio_util::sync::CancellationToken::new();

    // Start fingerprint cleanup task
    let cleanup_task_handle = start_fingerprint_cleanup_task(
        fingerprint_store.clone(),
        cleanup_interval_minutes,
        cleanup_shutdown_token.clone(),
    );
    info!("Fingerprint cleanup task started");

    // Initialize rate limiting
    let rate_limit_requests = parameter::get_u64_or_panic("RATE_LIMIT_REQUESTS_PER_MINUTE") as u32;
    let rate_limit_state = RateLimitState::new(rate_limit_requests, 60); // 60 seconds = 1 minute
    info!("Rate limiting initialized: {} requests per minute", rate_limit_requests);

    // Initialize Casbin service
    let casbin_service = match CasbinService::new().await {
        Ok(service) => {
            info!("Casbin service initialized successfully");
            service
        }
        Err(e) => {
            secure_log::secure_error!("Failed to initialize Casbin service", e);
            return Err(e);
        }
    };

    // Create shared Arc for Casbin service
    let casbin_service_arc = Arc::new(casbin_service);

    let casbin_state = CasbinState {
        enforcer: casbin_service_arc.enforcer(),
    };
    info!("Casbin state initialized");

    // Initialize GraphQL schema
    let graphql_schema = async_graphql::Schema::new(
        QueryRoot,
        MutationRoot,
        async_graphql::EmptySubscription,
    );

    // Initialize GraphQL state
    let db_conn_arc = Arc::new(connection);
    let graphql_state = GraphQLState::new(&db_conn_arc, graphql_schema);
    info!("GraphQL state initialized successfully");
    info!("GraphQL schema initialized");


    // Bind to the host address
    let listener = match tokio::net::TcpListener::bind(&host).await {
        Ok(listener) => {
            info!("Server successfully bound to {}", host);
            listener
        }
        Err(e) => {
            secure_log::secure_error!("Failed to bind to server address", e);
            return Err(e.into());
        }
    };

    // Start the server with graceful shutdown
    info!("Server starting...");

    // Create a channel for shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn a task to listen for shutdown signals
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("Received shutdown signal, initiating graceful shutdown...");
                // Cancel the cleanup task
                cleanup_shutdown_token.cancel();
                let _ = shutdown_tx.send(());
            }
            Err(err) => {
                secure_log::secure_error!("Unable to listen for shutdown signal", err);
            }
        }
    });

    // Initialize routes with error handling for JWT secret validation
    let app = match routes::root::routes(db_conn_arc, rate_limit_state, casbin_state, graphql_state, fingerprint_store).await {
        Ok(router) => router,
        Err(e) => {
            secure_log::secure_error!("Failed to initialize routes", e);
            return Err(Box::new(e) as Box<dyn std::error::Error>);
        }
    };

    // Start the server with shutdown signal
    match axum::serve(listener, app)
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
            // Wait for cleanup task to finish
            if let Err(e) = cleanup_task_handle.await {
                secure_log::secure_error!("Error waiting for cleanup task to finish", e);
            }
        })
        .await {
        Ok(_) => {
            info!("Server shutdown gracefully");
            Ok(())
        }
        Err(e) => {
            secure_log::secure_error!("Server error occurred", e);
            Err(Box::new(e) as Box<dyn std::error::Error>)
        }
    }
}
