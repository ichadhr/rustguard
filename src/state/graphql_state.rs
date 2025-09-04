use std::sync::Arc;
use crate::service::user_service::UserService;
use crate::graphql::schema::AppSchema;

#[derive(Clone)]
pub struct GraphQLState {
    pub schema: AppSchema,
    pub user_service: UserService,
}

impl GraphQLState {
    pub fn new(db_conn: &Arc<crate::config::database::Database>, schema: AppSchema) -> Self {
        Self {
            schema,
            user_service: UserService::new(db_conn),
        }
    }
}