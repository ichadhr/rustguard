use std::sync::Arc;
use casbin::CachedEnforcer;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct CasbinState {
    pub enforcer: Arc<RwLock<CachedEnforcer>>,
}