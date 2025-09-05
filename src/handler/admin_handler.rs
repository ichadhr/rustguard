use axum::{extract::Extension, Json};
use crate::response::app_response::SuccessResponse;
use crate::dto::admin_dto::{AddPolicyRequest, AddPolicyResponse, CheckPermissionRequest, CheckPermissionResponse};
use crate::entity::user::User;
use crate::service::casbin_service::CasbinService;
use crate::error::request_error::ValidatedRequest;
use std::sync::Arc;
use tokio::sync::RwLock;
use casbin::CachedEnforcer;
use tracing::info;

pub async fn add_policy(
    Extension(current_user): Extension<User>,
    Extension(enforcer): Extension<Arc<RwLock<CachedEnforcer>>>,
    ValidatedRequest(request): ValidatedRequest<AddPolicyRequest>,
) -> Json<SuccessResponse<AddPolicyResponse>> {
    // Create service instance from the shared enforcer
    let service = CasbinService {
        enforcer: Arc::clone(&enforcer),
    };

    let effect = request.effect.unwrap_or_else(|| "allow".to_string());

    match service.add_policy(vec![
        &request.subject,
        &request.object,
        &request.action,
        &effect
    ]).await {
        Ok(_) => Json(SuccessResponse::send(AddPolicyResponse {
            success: true,
            message: format!("Policy added: {} can {} on {} (by admin: {})",
                request.subject, request.action, request.object, current_user.email),
        })),
        Err(e) => {
            let error_response = AddPolicyResponse {
                success: false,
                message: format!("Failed to add policy: {}", e),
            };
            Json(SuccessResponse::send(error_response))
        }
    }
}

pub async fn check_permission(
    Extension(current_user): Extension<User>,
    Extension(enforcer): Extension<Arc<RwLock<CachedEnforcer>>>,
    ValidatedRequest(request): ValidatedRequest<CheckPermissionRequest>,
) -> Json<SuccessResponse<CheckPermissionResponse>> {
    // Create service instance from the shared enforcer
    let service = CasbinService {
        enforcer: Arc::clone(&enforcer),
    };

    let allowed = service.check_permission(&request.subject, &request.object, &request.action).await;

    // Log the permission check for audit purposes
    info!("SECURITY: Admin user ID: {} (email: {}) checked permission for {} on {}: {}",
        current_user.id, current_user.email, request.subject, request.object, request.action);

    Json(SuccessResponse::send(CheckPermissionResponse {
        allowed,
        subject: request.subject,
        object: request.object,
        action: request.action,
    }))
}