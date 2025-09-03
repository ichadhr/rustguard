use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenReadDto {
    pub token: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenWithRefreshDto {
    pub token: String,
    pub iat: i64,
    pub exp: i64,
    pub refresh_token: String,
    pub family_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenClaimsDto {
    pub sub: Uuid,
    pub email: String,
    pub iat: i64,
    pub exp: i64,
    pub fingerprint_hash: String,
    pub jti: String, // JWT ID for uniqueness and replay prevention
    pub iss: String, // Issuer
    pub aud: String, // Audience
}

#[derive(Clone, Serialize, Deserialize, Validate)]
pub struct RefreshTokenRequestDto {
    #[validate(length(
        min = 1,
        message = "Refresh token is required"
    ))]
    pub refresh_token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshTokenResponseDto {
    pub token: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Validate)]
pub struct LogoutRequestDto {
    #[validate(length(
        min = 1,
        message = "Refresh token is required"
    ))]
    pub refresh_token: String,
    #[serde(default)]
    pub logout_family: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LogoutResponseDto {
    pub message: String,
}