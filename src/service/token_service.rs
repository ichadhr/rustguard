use crate::config::parameter;
use crate::dto::token_dto::{TokenClaimsDto, TokenReadDto, TokenWithRefreshDto};
use crate::entity::user::User;
use crate::error::token_error::TokenError;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
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
        let secret = parameter::get("JWT_SECRET");

        // Validate JWT secret meets minimum security requirements (256 bits = 32 bytes)
        if secret.len() < 32 {
            return Err(TokenError::TokenCreationError(
                "JWT secret must be at least 32 bytes (256 bits) for security. Current length: ".to_string()
                    + &secret.len().to_string()
            ));
        }

        Ok(Self {
            secret,
            token_expiration_minutes: parameter::get_i64("JWT_TTL_IN_MINUTES"),
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

        decode::<TokenClaimsDto>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &validation,
        )
    }

    fn generate_token_with_fingerprint(&self, user: User, fingerprint_hash: &str) -> Result<TokenReadDto, TokenError> {
        let iat = chrono::Utc::now().timestamp();
        let exp = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(self.token_expiration_minutes))
            .ok_or_else(|| TokenError::TokenCreationError(
                "Token expiration calculation overflow".to_string()
            ))?
            .timestamp();

        let claims = TokenClaimsDto {
            sub: user.id,
            email: user.email,
            iat,
            exp,
            fingerprint_hash: fingerprint_hash.to_string(),
            jti: Uuid::now_v7().to_string(), // Unique JWT ID for replay prevention (time-ordered)
            iss: "jwt-fingerprint-framework".to_string(), // Issuer
            aud: "jwt-fingerprint-users".to_string(), // Audience
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
        .map_err(|e| TokenError::TokenCreationError(e.to_string()))?;

        Ok(TokenReadDto { token, iat, exp })
    }

    fn generate_token_with_refresh(&self, user: User, fingerprint_hash: &str) -> Result<TokenWithRefreshDto, TokenError> {
        use crate::service::refresh_token_service::{RefreshTokenService, RefreshTokenServiceTrait};

        let refresh_service = RefreshTokenService::new();
        refresh_service.create_token_with_refresh(user, fingerprint_hash)
    }

}
