use crate::config::logging::secure_log;
use crate::config::parameter;
use crate::dto::token_dto::{TokenClaimsDto, TokenReadDto, TokenWithRefreshDto};
use crate::entity::user::User;
use crate::error::token_error::TokenError;
use crate::service::refresh_token_service::{RefreshTokenService, RefreshTokenServiceTrait};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct TokenService {
    secret: String,
    token_expiration_minutes: i64,
}

pub trait TokenServiceTrait {
    fn new() -> Result<Self, TokenError> where Self: Sized;
    fn retrieve_token_claims(
        &self,
        token: &str,
    ) -> jsonwebtoken::errors::Result<TokenData<TokenClaimsDto>>;
    fn generate_token_with_fingerprint(&self, user: User, fingerprint_hash: &str) -> Result<TokenReadDto, TokenError>;
    fn generate_token_with_refresh(&self, user: User, fingerprint_hash: &str) -> Result<TokenWithRefreshDto, TokenError>;
}

impl TokenServiceTrait for TokenService {
    fn new() -> Result<Self, TokenError> {
        let secret = parameter::get_or_panic("JWT_SECRET");

        // Validate JWT secret meets minimum security requirements (256 bits = 32 bytes)
        if secret.len() < 32 {
            let error_msg = format!(
                "JWT secret must be at least 32 bytes (256 bits) for security. Current length: {}",
                secret.len()
            );
            secure_log::secure_error!("JWT secret validation failed", TokenError::TokenCreationError(error_msg.clone()));
            return Err(TokenError::TokenCreationError(error_msg));
        }

        let token_expiration_minutes = parameter::get_i64_or_panic("JWT_TTL_IN_MINUTES");
        info!("SECURITY: Token service initialized with TTL: {} minutes", token_expiration_minutes);
        secure_log::sensitive_debug!("JWT secret length validated: {} bytes", secret.len());

        Ok(Self {
            secret,
            token_expiration_minutes,
        })
    }
    fn retrieve_token_claims(
        &self,
        token: &str,
    ) -> jsonwebtoken::errors::Result<TokenData<TokenClaimsDto>> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["jwt-fingerprint-framework"]);
        validation.set_audience(&["jwt-fingerprint-users"]);
        validation.validate_exp = true;
        validation.validate_nbf = false; // Not using nbf claims
        validation.leeway = 30; // 30 seconds leeway for clock skew

        match decode::<TokenClaimsDto>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &validation,
        ) {
            Ok(token_data) => {
                info!("SECURITY: JWT token validated successfully for user ID: {} (email: {})", token_data.claims.sub, token_data.claims.email);
                secure_log::sensitive_debug!("JWT token validated for email: {}", token_data.claims.email);
                Ok(token_data)
            }
            Err(e) => {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        warn!("SECURITY: JWT token validation failed - expired token for user ID: {}", "unknown");
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        warn!("SECURITY: JWT token validation failed - invalid signature");
                    }
                    _ => {
                        warn!("SECURITY: JWT token validation failed - {}", e);
                    }
                }
                secure_log::secure_error!("JWT token validation error", e);
                Err(e)
            }
        }
    }

    fn generate_token_with_fingerprint(&self, user: User, fingerprint_hash: &str) -> Result<TokenReadDto, TokenError> {
        let iat = chrono::Utc::now().timestamp();
        let exp = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(self.token_expiration_minutes))
            .ok_or_else(|| {
                secure_log::secure_error!("Token expiration calculation failed", TokenError::TokenCreationError(
                    "Token expiration calculation overflow".to_string()
                ));
                TokenError::TokenCreationError(
                    "Token expiration calculation overflow".to_string()
                )
            })?
            .timestamp();

        let jti = Uuid::now_v7().to_string();
        let claims = TokenClaimsDto {
            sub: user.id,
            email: user.email.clone(),
            iat,
            exp,
            fingerprint_hash: fingerprint_hash.to_string(),
            jti: jti.clone(),
            iss: "jwt-fingerprint-framework".to_string(),
            aud: "jwt-fingerprint-users".to_string(),
        };

        match encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        ) {
            Ok(token) => {
                info!("SECURITY: JWT token generated successfully for user ID: {} (email: {}) with JTI: {}", user.id, user.email, jti);
                secure_log::sensitive_debug!("JWT token generated for email: {} with fingerprint hash: {}", user.email, fingerprint_hash);
                Ok(TokenReadDto { token, iat, exp })
            }
            Err(e) => {
                secure_log::secure_error!("JWT token generation failed", TokenError::TokenCreationError(e.to_string()));
                Err(TokenError::TokenCreationError(e.to_string()))
            }
        }
    }

    fn generate_token_with_refresh(&self, user: User, fingerprint_hash: &str) -> Result<TokenWithRefreshDto, TokenError> {
        let refresh_service = RefreshTokenService::new();
        refresh_service.create_token_with_refresh(user, fingerprint_hash)
    }

}
