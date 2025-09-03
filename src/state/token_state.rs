use crate::config::database::Database;
use crate::error::token_error::TokenError;
use crate::repository::user_repository::{UserRepository, UserRepositoryTrait};
use crate::service::token_service::{TokenService, TokenServiceTrait};
use crate::service::fingerprint_service::{FingerprintStore, InMemoryFingerprintStore};
use std::sync::Arc;

#[derive(Clone)]
pub struct TokenState {
    pub token_service: TokenService,
    pub user_repo: UserRepository,
    pub fingerprint_store: Arc<dyn FingerprintStore>,
}

impl TokenState {
    pub fn new(db_conn: &Arc<Database>) -> Result<Self, TokenError> {
        Ok(Self {
            token_service: TokenService::new()?,
            user_repo: UserRepository::new(db_conn),
            fingerprint_store: InMemoryFingerprintStore::new_shared(),
        })
    }
}
