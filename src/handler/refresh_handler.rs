use crate::config::logging::secure_log;
use crate::dto::token_dto::{RefreshTokenRequestDto, RefreshTokenResponseDto, LogoutRequestDto, LogoutResponseDto};
use crate::error::{api_error::ApiError, request_error::ValidatedRequest, token_error::TokenError};
use crate::repository::user_repository::UserRepositoryTrait;
use crate::service::refresh_token_service::{RefreshTokenService, RefreshTokenServiceTrait};
use crate::service::token_service::TokenServiceTrait;
use crate::state::auth_state::AuthState;
use axum::{extract::State, Json};

/// Refresh access token using refresh token
pub async fn refresh_token(
    State(state): State<AuthState>,
    ValidatedRequest(payload): ValidatedRequest<RefreshTokenRequestDto>,
) -> Result<Json<RefreshTokenResponseDto>, ApiError> {
    secure_log::sensitive_debug!("Token refresh attempt for refresh token: {}", &payload.refresh_token[..8]);

    // Find user by refresh token
    let refresh_service = RefreshTokenService::new();
    let refresh_token_hash = refresh_service.hash_refresh_token(&payload.refresh_token);

    // Find user by refresh token hash
    let user = match state.user_repo.find_by_refresh_token_hash(&refresh_token_hash).await {
        Some(user) => user,
        None => {
            secure_log::secure_error!("Refresh token not found in database");
            return Err(TokenError::MissingRefreshToken)?;
        }
    };

    // Validate refresh token using service
    match state.refresh_token_service.validate_refresh_token(&refresh_token_hash, user.id, &state.user_repo).await {
        Ok(true) => {
            secure_log::sensitive_debug!("Refresh token validated for user: {}", user.email);
        },
        Ok(false) => {
            secure_log::secure_error!("Refresh token has expired for user: {}", user.email);
            return Err(TokenError::RefreshTokenExpired)?;
        },
        Err(e) => {
            secure_log::secure_error!("Refresh token validation error for user", e);
            return Err(e)?;
        }
    }

    // Generate new access token (without fingerprint for refresh endpoint)
    let token_response = match state.token_service.generate_token_with_fingerprint(user.clone(), "") {
        Ok(token) => token,
        Err(e) => {
            secure_log::secure_error!("Failed to generate new access token", e);
            return Err(e)?;
        }
    };

    // Check if token rotation is enabled
    let mut response = RefreshTokenResponseDto {
        token: token_response.token,
        iat: token_response.iat,
        exp: token_response.exp,
        refresh_token: None,
    };

    if refresh_service.should_rotate_token() {
        // Generate new refresh token
        let new_refresh_token = refresh_service.generate_refresh_token();
        let new_refresh_token_hash = refresh_service.hash_refresh_token(&new_refresh_token);
        let expires_at = refresh_service.calculate_expiration();

        // Get the family ID from the current token
        let family_id = user.refresh_token_family
            .as_ref()
            .ok_or_else(|| {
                secure_log::secure_error!("No family ID found for token rotation");
                TokenError::InvalidRefreshToken
            })?;

        // Store new refresh token
        match state.user_repo.store_refresh_token(
            user.id,
            &new_refresh_token_hash,
            family_id,
            expires_at,
        ).await {
            Ok(_) => {
                secure_log::sensitive_debug!("New refresh token stored for user: {}", user.email);
                response.refresh_token = Some(new_refresh_token);
            },
            Err(e) => {
                secure_log::secure_error!("Failed to store new refresh token", e);
                return Err(ApiError::Db(crate::error::db_error::DbError::SomethingWentWrong(e.to_string())));
            }
        }
    }

    secure_log::sensitive_debug!("Token refresh successful for user: {}", user.email);
    Ok(Json(response))
}

/// Logout user by invalidating refresh token
pub async fn logout(
    State(state): State<AuthState>,
    ValidatedRequest(payload): ValidatedRequest<LogoutRequestDto>,
) -> Result<Json<LogoutResponseDto>, ApiError> {
    secure_log::sensitive_debug!("Logout attempt");

    // Find user by refresh token
    let refresh_service = RefreshTokenService::new();
    let refresh_token_hash = refresh_service.hash_refresh_token(&payload.refresh_token);

    let user = match state.user_repo.find_by_refresh_token_hash(&refresh_token_hash).await {
        Some(user) => user,
        None => {
            secure_log::secure_error!("Refresh token not found for logout");
            return Err(TokenError::MissingRefreshToken)?;
        }
    };

    if payload.logout_family {
        // Invalidate entire family
        let family_id = user.refresh_token_family
            .as_ref()
            .ok_or_else(|| {
                secure_log::secure_error!("No family ID found for family logout");
                TokenError::InvalidRefreshToken
            })?;

        match state.user_repo.invalidate_refresh_family(family_id, user.id).await {
            Ok(_) => {
                secure_log::sensitive_debug!("Refresh token family '{}' invalidated for user: {}", family_id, user.email);
            },
            Err(e) => {
                secure_log::secure_error!("Failed to invalidate refresh token family", e);
                return Err(ApiError::Db(crate::error::db_error::DbError::SomethingWentWrong(e.to_string())));
            }
        }
    } else {
        // Invalidate single token
        match state.user_repo.invalidate_refresh_token(&refresh_token_hash, user.id).await {
            Ok(_) => {
                secure_log::sensitive_debug!("Refresh token invalidated for user: {}", user.email);
            },
            Err(e) => {
                secure_log::secure_error!("Failed to invalidate refresh token", e);
                return Err(ApiError::Db(crate::error::db_error::DbError::SomethingWentWrong(e.to_string())));
            }
        }
    }

    let response = LogoutResponseDto {
        message: if payload.logout_family {
            "Logged out from all sessions successfully"
        } else {
            "Logged out successfully"
        }.to_string(),
    };

    secure_log::sensitive_debug!("Logout successful for user: {}", user.email);
    Ok(Json(response))
}
