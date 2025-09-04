use crate::error::authorization_error::AuthorizationError;
use axum::extract::State;
use axum::{http::Request, middleware::Next, response::IntoResponse};
use std::sync::Arc;
use tokio::sync::RwLock;
use casbin::{CachedEnforcer, CoreApi, MgmtApi};
use crate::config::logging::secure_log;
use tracing::info;

pub async fn authorize(
    State(enforcer): State<Arc<RwLock<CachedEnforcer>>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<impl IntoResponse, AuthorizationError> {
    // Extract CasbinVals from request extensions (set by auth middleware)
    let casbin_vals = req.extensions()
        .get::<axum_casbin::CasbinVals>()
        .ok_or_else(|| AuthorizationError::PolicyEvaluationFailed {
            reason: "CasbinVals not found in request extensions".to_string(),
        })?;

    let subject = &casbin_vals.subject;
    let object = req.uri().path();
    let action = req.method().as_str();

    info!("Authorization check for subject: {}", subject);

    // Check permission using Casbin
    let enforcer_guard = enforcer.read().await;

    // Debug logging
    info!("Casbin enforcement - Subject: {}, Object: {}, Action: {}", subject, object, action);
    info!("Full request URI: {}", req.uri());

    let allowed = enforcer_guard.enforce((subject, object, action))
        .map_err(|e| {
            secure_log::secure_error!("Casbin enforcement failed", e);
            AuthorizationError::PolicyEvaluationFailed {
                reason: "Casbin enforcement failed".to_string(),
            }
        })?;

    info!("Casbin enforcement result: {}", allowed);

    if !allowed {
        secure_log::secure_error!("Access denied for subject", subject);
        return Err(AuthorizationError::AccessDenied {
            message: "Access denied".to_string(),
        });
    }

    info!("Authorization granted for subject: {}", subject);

    // Permission granted, continue to next middleware/handler
    Ok(next.run(req).await)
}