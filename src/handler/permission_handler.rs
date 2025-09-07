use axum::extract::Extension;
use crate::response::app_response::SuccessResponse;
use crate::dto::policy_dto::{CheckPermissionRequest, CheckPermissionResponse};
use crate::entity::user::User;
use crate::service::casbin_service::CasbinService;
use crate::error::request_error::ValidatedRequest;
use std::sync::Arc;
use tokio::sync::RwLock;
use casbin::CachedEnforcer;
use tracing::info;

pub async fn check_permission(
    Extension(current_user): Extension<User>,
    Extension(enforcer): Extension<Arc<RwLock<CachedEnforcer>>>,
    ValidatedRequest(request): ValidatedRequest<CheckPermissionRequest>,
) -> SuccessResponse<CheckPermissionResponse> {
    // Create service instance from the shared enforcer
    let service = CasbinService {
        enforcer: Arc::clone(&enforcer),
    };

    let allowed = service.check_permission(&request.subject, &request.object, &request.action).await;

    // Log the permission check for audit purposes
    info!("SECURITY: User ID: {} (email: {}) checked permission for {} on {}: {}",
        current_user.id, current_user.email, request.subject, request.object, request.action);

    SuccessResponse::send(CheckPermissionResponse {
        allowed,
        subject: request.subject,
        object: request.object,
        action: request.action,
    })
}