use crate::config::logging::secure_log;
use crate::dto::user_dto::{UserReadDto, UserRegisterDto};
use crate::error::{api_error::ApiError, request_error::ValidatedRequest};
use crate::state::user_state::UserState;
use axum::{extract::State, Json};

pub async fn register(
    State(state): State<UserState>,
    ValidatedRequest(payload): ValidatedRequest<UserRegisterDto>,
) -> Result<Json<UserReadDto>, ApiError> {
    secure_log::sensitive_debug!("User registration attempt for email: {}", payload.email);

    match state.user_service.create_user(payload).await {
        Ok(user) => {
            secure_log::sensitive_debug!("User registration completed for email: {}", user.email);
            Ok(Json(user))
        },
        Err(e) => {
            secure_log::secure_error!("User registration failed", e);
            Err(e)
        }
    }
}
