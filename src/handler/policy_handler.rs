use axum::{extract::Extension, http::StatusCode};
use crate::config::logging::secure_log;
use crate::response::app_response::SuccessResponse;
use crate::dto::policy_dto::{AddPolicyRequest, AddPolicyResponse};
use crate::entity::user::User;
use crate::service::casbin_service::CasbinService;
use crate::error::{AppError, request_error::ValidatedRequest};
use std::sync::Arc;
use tokio::sync::RwLock;
use casbin::CachedEnforcer;

pub async fn add_policy(
    Extension(current_user): Extension<User>,
    Extension(enforcer): Extension<Arc<RwLock<CachedEnforcer>>>,
    ValidatedRequest(request): ValidatedRequest<AddPolicyRequest>,
) -> Result<SuccessResponse<AddPolicyResponse>, AppError> {
    // Create service instance from the shared enforcer
    let service = CasbinService {
        enforcer: Arc::clone(&enforcer),
    };

    let effect = request.effect.unwrap_or_else(|| "allow".to_string());

    service.add_policy(vec![
        &request.subject,
        &request.object,
        &request.action,
        &effect
    ]).await.map_err(|e| AppError::Internal(format!("Failed to add policy: {}", e)))?;

    secure_log::sensitive_debug!("Policy added successfully for subject: {}", request.subject);
    let json_response = SuccessResponse::send(AddPolicyResponse {
        success: true,
        message: format!("Policy added: {} can {} on {} (by user: {})",
            request.subject, request.action, request.object, current_user.email),
    }).with_status(StatusCode::CREATED);
    Ok(json_response)
}