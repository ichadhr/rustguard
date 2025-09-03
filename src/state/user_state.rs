use crate::config::database::Database;
use crate::service::user_service::UserService;
use std::sync::Arc;

#[derive(Clone)]
pub struct UserState {
    pub user_service: UserService,
}

impl UserState {
    pub fn new(db_conn: &Arc<Database>) -> Self {
        Self {
            user_service: UserService::new(db_conn),
        }
    }
}
