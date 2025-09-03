use crate::error::{api_error::ApiError, token_error::TokenError, user_error::UserError};
use crate::repository::user_repository::UserRepositoryTrait;
use crate::service::token_service::TokenServiceTrait;
use crate::service::fingerprint_service::FingerprintService;
use crate::state::token_state::TokenState;
use axum::extract::State;
use axum::{http, http::Request, middleware::Next, response::IntoResponse};
use jsonwebtoken::errors::ErrorKind;
use tracing::{info, warn, error};

pub async fn auth(
    State(state): State<TokenState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .or_else(|| req.headers().get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    info!("Authentication attempt from IP: {}", client_ip);

    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or_else(|| {
            warn!("Missing authorization header from IP: {}", client_ip);
            TokenError::MissingToken
        })?;

    // Early return for missing tokens to avoid unnecessary processing
    if auth_header.is_empty() {
        warn!("Empty authorization token from IP: {}", client_ip);
        return Err(TokenError::InvalidToken("".to_string()))?;
    }

    let token = auth_header;
    info!("Validating JWT token for IP: {}", client_ip);

    match state.token_service.retrieve_token_claims(token) {
        Ok(token_data) => {
            info!("JWT token validated successfully for user: {}", token_data.claims.email);

            // Extract fingerprint from HttpOnly cookie
            let cookie_header = req
                .headers()
                .get(http::header::COOKIE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            let fingerprint = FingerprintService::extract_fingerprint_from_cookie(cookie_header)
                .ok_or_else(|| {
                    warn!("Missing fingerprint cookie for user: {} from IP: {}", token_data.claims.email, client_ip);
                    TokenError::MissingFingerprint
                })?;

            // Hash the fingerprint and compare with JWT claims
            let fingerprint_hash = FingerprintService::hash_fingerprint(&fingerprint);

            if fingerprint_hash != token_data.claims.fingerprint_hash {
                warn!("Fingerprint hash mismatch for user: {} from IP: {}", token_data.claims.email, client_ip);
                return Err(TokenError::InvalidFingerprint)?;
            }

            // Validate fingerprint against in-memory store
            let is_valid = match state.fingerprint_store.validate_fingerprint(
                &fingerprint_hash,
                token_data.claims.sub,
            ).await {
                Ok(valid) => valid,
                Err(e) => {
                    error!("Fingerprint validation error for user: {}: {}", token_data.claims.email, e);
                    return Err(ApiError::Fingerprint(e.to_string()));
                }
            };

            if !is_valid {
                warn!("Invalid fingerprint validation for user: {} from IP: {}", token_data.claims.email, client_ip);
                return Err(TokenError::InvalidFingerprint)?;
            }

            // Find user and continue
            let user = state.user_repo.find_by_email(token_data.claims.email.clone()).await;
            match user {
                Some(user) => {
                    info!("Authentication successful for user: {} from IP: {}", token_data.claims.email, client_ip);
                    req.extensions_mut().insert(user);
                    Ok(next.run(req).await)
                }
                None => {
                    warn!("User not found in database: {} from IP: {}", token_data.claims.email, client_ip);
                    Err(UserError::UserNotFound)?
                }
            }
        }
        Err(err) => {
            match err.kind() {
                ErrorKind::ExpiredSignature => {
                    warn!("Expired JWT token from IP: {}", client_ip);
                    Err(TokenError::TokenExpired)?
                }
                _ => {
                    warn!("Invalid JWT token from IP: {}", client_ip);
                    Err(TokenError::InvalidToken(token.to_string()))?
                }
            }
        }
    }
}
