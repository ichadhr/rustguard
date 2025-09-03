use std::sync::Arc;
use crate::config::{database, parameter};
use crate::config::database::DatabaseTrait;
use crate::handler::health_handler;
use crate::service::fingerprint_service::{start_cleanup_task, InMemoryFingerprintStore};
use tracing::{error, info};

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber for structured logging
    tracing_subscriber::fmt::init();

    info!("Starting Rust JWT Fingerprinting Framework...");

    // Initialize configuration
    parameter::init();
    info!("Configuration initialized");

    // Initialize logging configuration
    crate::config::logging::init();
    info!("Logging configuration initialized");

    // Initialize health check start time
    health_handler::init_start_time();

    // Initialize database connection
    let connection = match database::Database::init().await {
        Ok(conn) => {
            info!("Database connection established successfully");
            conn
        }
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Err(Box::new(e) as Box<dyn std::error::Error>);
        }
    };

    // Get server configuration
    let server_address = parameter::get("SERVER_ADDRESS");
    let server_port = parameter::get("SERVER_PORT");
    let host = format!("{}:{}", server_address, server_port);
    info!("Server will bind to: {}", host);

    // Initialize shared fingerprint store for cleanup task
    let fingerprint_store = InMemoryFingerprintStore::new_shared();
    info!("Fingerprint store initialized");

    // Get cleanup interval from configuration
    let cleanup_interval_minutes = parameter::get_u64("FINGERPRINT_CLEANUP_INTERVAL_MINUTES");
    info!("Fingerprint cleanup interval: {} minutes", cleanup_interval_minutes);

    // Create cancellation token for graceful shutdown
    let cleanup_shutdown_token = tokio_util::sync::CancellationToken::new();

    // Start fingerprint cleanup task
    let cleanup_task_handle = start_cleanup_task(
        fingerprint_store.clone(),
        cleanup_interval_minutes,
        cleanup_shutdown_token.clone(),
    );
    info!("Fingerprint cleanup task started");

    // Bind to the host address
    let listener = match tokio::net::TcpListener::bind(&host).await {
        Ok(listener) => {
            info!("Server successfully bound to {}", host);
            listener
        }
        Err(e) => {
            error!("Failed to bind to {}: {}", host, e);
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
                error!("Unable to listen for shutdown signal: {}", err);
            }
        }
    });

    // Initialize routes with error handling for JWT secret validation
    let app = match routes::root::routes(Arc::new(connection)) {
        Ok(router) => router,
        Err(e) => {
            error!("Failed to initialize routes: {}", e);
            return Err(Box::new(e) as Box<dyn std::error::Error>);
        }
    };

    // Start the server with shutdown signal
    match axum::serve(listener, app)
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
            // Wait for cleanup task to finish
            if let Err(e) = cleanup_task_handle.await {
                error!("Error waiting for cleanup task to finish: {}", e);
            }
        })
        .await {
        Ok(_) => {
            info!("Server shutdown gracefully");
            Ok(())
        }
        Err(e) => {
            error!("Server error: {}", e);
            Err(Box::new(e) as Box<dyn std::error::Error>)
        }
    }
}
