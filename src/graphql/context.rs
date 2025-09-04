use crate::entity::user::User;
use crate::service::user_service::UserService;
use crate::service::casbin_service::CasbinService;
use async_graphql::{Error, Result};
use std::sync::Arc;

pub struct GraphQLContext {
    pub user: Option<User>,
    pub user_service: UserService,
    pub casbin_service: Arc<CasbinService>,
}

impl GraphQLContext {
    pub fn require_auth(&self) -> Result<&User> {
        self.user.as_ref().ok_or_else(|| {
            Error::new("Authentication required")
        })
    }

    pub fn require_role(&self, role: &str) -> Result<&User> {
        let user = self.require_auth()?;
        if user.role != role {
            return Err(Error::new("Insufficient permissions"));
        }
        Ok(user)
    }

    pub fn map_error<T>(&self, result: Result<T, crate::error::api_error::ApiError>, field: &str) -> Result<T, Error> {
        result.map_err(|e| crate::graphql::utils::map_api_error_to_graphql(e, Some(field)))
    }
}
