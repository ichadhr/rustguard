use crate::config::database::Database;
use crate::error::token_error::TokenError;
use crate::repository::user_repository::{UserRepository, UserRepositoryTrait};
use crate::service::token_service::{TokenService};
use crate::service::fingerprint_service::{FingerprintStore, InMemoryFingerprintStore};
use std::sync::Arc;

#[derive(Clone)]
pub struct TokenState {
    pub token_service: TokenService,
    pub user_repo: UserRepository,
    pub fingerprint_store: Arc<dyn FingerprintStore>,
}

impl TokenState {
    pub fn new_with_token_service(db_conn: &Arc<Database>, token_service: TokenService) -> Result<Self, TokenError> {
        Ok(Self {
            token_service,
            user_repo: UserRepository::new(db_conn),
            fingerprint_store: InMemoryFingerprintStore::new_shared(),
        })
    }

    pub fn new_with_token_service_and_fingerprint_store(
        db_conn: &Arc<Database>,
        token_service: TokenService,
        fingerprint_store: Arc<dyn FingerprintStore>
    ) -> Result<Self, TokenError> {
        Ok(Self {
            token_service,
            user_repo: UserRepository::new(db_conn),
            fingerprint_store,
        })
    }
}
