use crate::config::logging::secure_log;
use crate::dto::{token_dto::TokenWithRefreshDto, user_dto::UserLoginDto};
use crate::error::{AppError, db_error::DbError, request_error::ValidatedRequest, user_error::UserError};
use crate::repository::user_repository::UserRepositoryTrait;
use crate::response::app_response::SuccessResponse;
use crate::service::refresh_token_service::{RefreshTokenService, RefreshTokenServiceTrait};
use crate::service::token_service::TokenServiceTrait;
use crate::service::fingerprint_service::FingerprintService;
use crate::state::auth_state::AuthState;
use axum::{extract::State, http, http::HeaderMap};

pub async fn auth(
    State(state): State<AuthState>,
    headers: HeaderMap,
    ValidatedRequest(payload): ValidatedRequest<UserLoginDto>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    secure_log::sensitive_debug!("Login attempt for email: {}", payload.email);

    let user = state
        .user_repo
        .find_by_email(payload.email.clone())
        .await
        .ok_or_else(|| {
            secure_log::sensitive_debug!("Login failed - user not found: {}", payload.email);
            UserError::UserNotFound
        })?;

    match state.user_service.verify_password(&user, &payload.password).await? {
        true => {
            secure_log::sensitive_debug!("Password verification successful for user: {}", payload.email);

            // Generate unique fingerprint for this session
            let fingerprint = FingerprintService::generate_fingerprint();
            let fingerprint_hash = FingerprintService::hash_fingerprint(&fingerprint);
            secure_log::sensitive_debug!("Generated fingerprint for user: {}", payload.email);

            // Extract client information for security tracking
            let ip_address = extract_client_ip(&headers);
            let user_agent = extract_user_agent(&headers);

            // Store fingerprint in memory with client info
            match state.fingerprint_store.store_fingerprint(
                user.id,
                &fingerprint_hash,
                ip_address,
                user_agent,
                30, // 30 minutes TTL
            ).await {
                Ok(_) => {
                    secure_log::sensitive_debug!("Fingerprint stored successfully for user: {}", payload.email);
                },
                Err(e) => {
                    secure_log::secure_error!("Failed to store fingerprint for user", e);
                    return Err(AppError::Fingerprint(e.to_string()));
                }
            }

            // Create JWT with refresh token
            let token_response: TokenWithRefreshDto = state.token_service.generate_token_with_refresh(user.clone(), &fingerprint_hash)?;
            secure_log::sensitive_debug!("JWT and refresh tokens generated successfully for user: {}", payload.email);

            // Store refresh token in database
            let refresh_service = RefreshTokenService::new();
            let refresh_token_hash = refresh_service.hash_refresh_token(&token_response.refresh_token);
            let expires_at = refresh_service.calculate_expiration();

            match state.user_repo.store_refresh_token(
                user.id,
                &refresh_token_hash,
                &token_response.family_id,
                expires_at,
            ).await {
                Ok(_) => {
                    secure_log::sensitive_debug!("Refresh token stored successfully for user: {}", payload.email);
                },
                Err(e) => {
                    secure_log::secure_error!("Failed to store refresh token for user", e);
                    return Err(AppError::Db(DbError::SomethingWentWrong(e.to_string())));
                }
            }

            // Create HttpOnly cookie with raw fingerprint
            let cookie_value = FingerprintService::create_fingerprint_cookie(&fingerprint);

            // Return response with cookie and SuccessResponse
            let json_response = SuccessResponse::send(token_response);
            let response = (
                [(http::header::SET_COOKIE, cookie_value)],
                json_response,
            );

            secure_log::sensitive_debug!("Login successful for user: {}", payload.email);
            Ok(response)
        },
        false => {
            secure_log::sensitive_debug!("Invalid password for user: {}", payload.email);
            Err(UserError::InvalidPassword)?
        }
    }
}

/// Extract client IP address from request headers
/// Checks common proxy headers in order of preference
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    // Check X-Forwarded-For header (most common with load balancers/proxies)
    if let Some(forwarded_for) = headers.get("x-forwarded-for")
        && let Ok(forwarded_str) = forwarded_for.to_str() {
        // X-Forwarded-For can contain multiple IPs, take the first one
        if let Some(first_ip) = forwarded_str.split(',').next() {
            let ip = first_ip.trim();
            if !ip.is_empty() && ip != "unknown" {
                return Some(ip.to_string());
            }
        }
    }

    // Check X-Real-IP header (used by nginx)
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(real_ip_str) = real_ip.to_str()
        && !real_ip_str.is_empty() && real_ip_str != "unknown" {
        return Some(real_ip_str.to_string());
    }

    // Check X-Client-IP header (used by some proxies)
    if let Some(client_ip) = headers.get("x-client-ip")
        && let Ok(client_ip_str) = client_ip.to_str()
        && !client_ip_str.is_empty() && client_ip_str != "unknown" {
        return Some(client_ip_str.to_string());
    }

    // Check CF-Connecting-IP header (Cloudflare)
    if let Some(cf_ip) = headers.get("cf-connecting-ip")
        && let Ok(cf_ip_str) = cf_ip.to_str()
        && !cf_ip_str.is_empty() && cf_ip_str != "unknown" {
        return Some(cf_ip_str.to_string());
    }

    None
}

/// Extract user agent from request headers
fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .map(|ua| ua.to_string())
        .filter(|ua| !ua.is_empty())
}
