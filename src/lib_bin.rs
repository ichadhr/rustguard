//! Binary-specific utilities
//!
//! This module contains functions that are only used by the binary
//! and not exposed in the library API.

use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tokio::task::JoinHandle;

use crate::service::fingerprint_service::FingerprintStore;

/// Background cleanup task for fingerprint store with graceful shutdown
pub fn start_fingerprint_cleanup_task(
    store: Arc<dyn FingerprintStore>,
    interval_minutes: u64,
    shutdown_token: CancellationToken,
) -> JoinHandle<()> {
    let interval_duration = std::time::Duration::from_secs(interval_minutes * 60);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval_duration);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match store.cleanup_expired().await {
                        Ok(cleaned) => {
                            if cleaned > 0 {
                                tracing::info!("Cleaned up {} expired fingerprints", cleaned);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error during fingerprint cleanup: {}", e);
                        }
                    }
                }
                _ = shutdown_token.cancelled() => {
                    tracing::info!("Fingerprint cleanup task received shutdown signal, stopping gracefully");
                    break;
                }
            }
        }

        tracing::info!("Fingerprint cleanup task stopped");
    })
}