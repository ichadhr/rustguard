use crate::config::database::DatabaseTrait;
use crate::config::logging::secure_log;
use crate::response::app_response::SuccessResponse;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tracing::info;
use sys_info;


#[derive(Serialize, Deserialize, Debug)]
pub struct HealthStatus {
    pub status: String,
    pub timestamp: String,
    pub uptime_seconds: u64,
    pub version: String,
    pub database: DatabaseHealth,
    pub fingerprint_store: FingerprintStoreHealth,
    pub memory_usage: Option<MemoryUsage>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DatabaseHealth {
    pub status: String,
    pub response_time_ms: Option<u128>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FingerprintStoreHealth {
    pub status: String,
    pub active_fingerprints: Option<usize>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MemoryUsage {
    pub resident_set_size_kb: Option<u64>,
    pub virtual_memory_size_kb: Option<u64>,
}

static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

pub fn init_start_time() {
    START_TIME.set(Instant::now()).ok();
}

pub fn get_uptime_seconds() -> u64 {
    START_TIME
        .get()
        .map(|start| start.elapsed().as_secs())
        .unwrap_or(0)
}

pub async fn health_check(
    State(db): State<Arc<crate::config::database::Database>>,
) -> Json<SuccessResponse<HealthStatus>> {
    let start_time = Instant::now();
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Check database health
    let database_health = check_database_health(&db, start_time).await;

    // Check fingerprint store health (simplified - would need access to store)
    let fingerprint_health = FingerprintStoreHealth {
        status: "unknown".to_string(),
        active_fingerprints: None,
        error: Some("Fingerprint store health check not yet implemented".to_string()),
    };

    // Get memory usage (simplified)
    let memory_usage = get_memory_usage();

    let uptime_seconds = get_uptime_seconds();

    let status = if database_health.status == "healthy" {
        "healthy"
    } else {
        "unhealthy"
    };

    Json(SuccessResponse::send(HealthStatus {
        status: status.to_string(),
        timestamp,
        uptime_seconds,
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: database_health,
        fingerprint_store: fingerprint_health,
        memory_usage: Some(memory_usage),
    }))
}

async fn check_database_health(
    db: &Arc<crate::config::database::Database>,
    start_time: Instant,
) -> DatabaseHealth {
    // Simple database connectivity check
    match db.get_pool().acquire().await {
        Ok(_) => {
            let response_time = start_time.elapsed().as_millis();
            info!("Database health check passed in {}ms", response_time);
            DatabaseHealth {
                status: "healthy".to_string(),
                response_time_ms: Some(response_time),
                error: None,
            }
        }
        Err(e) => {
            secure_log::secure_error!("Database health check failed", e);
            DatabaseHealth {
                status: "unhealthy".to_string(),
                response_time_ms: None,
                error: Some(e.to_string()),
            }
        }
    }
}

fn get_memory_usage() -> MemoryUsage {
    // Try to get memory usage information using sys-info
    match sys_info::mem_info() {
        Ok(mem) => {
            MemoryUsage {
                resident_set_size_kb: Some(mem.total as u64 / 1024), // Convert to KB
                virtual_memory_size_kb: Some(mem.free as u64 / 1024), // Convert to KB
            }
        }
        Err(_) => {
            // Fallback if sys-info fails
            MemoryUsage {
                resident_set_size_kb: None,
                virtual_memory_size_kb: None,
            }
        }
    }
}

pub async fn detailed_health_check(
    State(db): State<Arc<crate::config::database::Database>>,
) -> Json<SuccessResponse<serde_json::Value>> {
    let basic_health = health_check(State(db)).await;

    // Add more detailed checks here
    let mut details = match serde_json::to_value(&basic_health.0) {
        Ok(value) => value,
        Err(e) => {
            secure_log::secure_error!("Failed to serialize health status", e);
            return Json(SuccessResponse::send(serde_json::json!({
                "status": "error",
                "message": "Failed to generate detailed health report",
                "error": e.to_string()
            })));
        }
    };

    // Add configuration status
    if let Some(obj) = details.as_object_mut() {
        obj.insert(
            "configuration".to_string(),
            serde_json::json!({
                "status": "loaded",
                "environment_variables": crate::config::parameter::get_all().len()
            }),
        );

        // Add system information
        let build_profile = if cfg!(debug_assertions) { "debug" } else { "release" };
        obj.insert(
            "system".to_string(),
            serde_json::json!({
                "rust_version": env!("CARGO_PKG_VERSION"),
                "build_profile": build_profile
            }),
        );
    }

    Json(SuccessResponse::send(details))
}