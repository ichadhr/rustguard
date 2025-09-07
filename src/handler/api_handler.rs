use crate::config::parameter;
use crate::response::app_response::{SuccessResponse, ErrorResponse};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiInfo {
    pub app_name: String,
    pub version: String,
    pub description: String,
}

pub async fn api_info() -> SuccessResponse<ApiInfo> {
    let app_name = parameter::get_optional("APP_NAME")
        .unwrap_or_else(|| "RustGuard".to_string());

    let version = env!("CARGO_PKG_VERSION").to_string();

    SuccessResponse::send(ApiInfo {
        app_name,
        version,
        description: "API".to_string(),
    })
}

pub async fn not_found() -> impl axum::response::IntoResponse {
    ErrorResponse::send("Endpoint not found".to_string())
        .with_status(StatusCode::NOT_FOUND)
}