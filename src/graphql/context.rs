use crate::entity::user::User;
use crate::error::api_error::ApiError;
use crate::graphql::utils;
use crate::service::user_service::UserService;
use async_graphql::{Error, Result};

pub struct GraphQLContext {
    pub user: Option<User>,
    pub user_service: UserService,
}

impl GraphQLContext {
    pub fn require_auth(&self) -> Result<&User> {
        self.user.as_ref().ok_or_else(|| {
            Error::new("Authentication required")
        })
    }

    pub fn map_error<T>(&self, result: Result<T, ApiError>, field: &str) -> Result<T, Error> {
        result.map_err(|e| utils::map_api_error_to_graphql(e, Some(field)))
    }
}
