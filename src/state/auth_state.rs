use crate::config::database::Database;
use crate::error::token_error::TokenError;
use crate::repository::user_repository;
use crate::repository::user_repository::UserRepositoryTrait;
use crate::service::token_service::{TokenService};
use crate::service::user_service::UserService;
use crate::service::refresh_token_service::{RefreshTokenService, RefreshTokenServiceTrait};
use crate::service::fingerprint_service::{FingerprintStore, InMemoryFingerprintStore};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthState {
    pub(crate) token_service: TokenService,
    pub(crate) user_repo: user_repository::UserRepository,
    pub(crate) user_service: UserService,
    pub(crate) refresh_token_service: RefreshTokenService,
    pub(crate) fingerprint_store: Arc<dyn FingerprintStore>,
}

impl AuthState {
    pub fn new_with_token_service(db_conn: &Arc<Database>, token_service: TokenService) -> Result<AuthState, TokenError> {
        Ok(Self {
            token_service,
            user_service: UserService::new(db_conn),
            user_repo: user_repository::UserRepository::new(db_conn),
            refresh_token_service: RefreshTokenService::new(),
            fingerprint_store: InMemoryFingerprintStore::new_shared(),
        })
    }

    pub fn new_with_token_service_and_fingerprint_store(
        db_conn: &Arc<Database>,
        token_service: TokenService,
        fingerprint_store: Arc<dyn FingerprintStore>
    ) -> Result<AuthState, TokenError> {
        Ok(Self {
            token_service,
            user_service: UserService::new(db_conn),
            user_repo: user_repository::UserRepository::new(db_conn),
            refresh_token_service: RefreshTokenService::new(),
            fingerprint_store,
        })
    }
}
