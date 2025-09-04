use crate::config::database::Database;
use crate::error::token_error::TokenError;
use crate::service::user_service::UserService;
use crate::service::casbin_service::CasbinService;
use crate::graphql::schema::AppSchema;
use std::sync::Arc;

#[derive(Clone)]
pub struct GraphQLState {
    pub schema: AppSchema,
    pub user_service: UserService,
    pub casbin_service: Arc<CasbinService>,
}

impl GraphQLState {
    pub fn new_with_casbin_service(db_conn: &Arc<Database>, schema: AppSchema, casbin_service: Arc<CasbinService>) -> Result<GraphQLState, TokenError> {
        Ok(Self {
            schema,
            user_service: UserService::new(db_conn),
            casbin_service,
        })
    }
}