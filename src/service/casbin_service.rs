use casbin::{CachedEnforcer, CoreApi, DefaultModel, MgmtApi};
use sqlx_adapter::SqlxAdapter;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::config::parameter;

pub struct CasbinService {
    pub enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl CasbinService {
    pub async fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let database_url = parameter::get("DATABASE_URL");

        let adapter = SqlxAdapter::new(&database_url, 8).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let model = DefaultModel::from_file("src/casbin/model.conf").await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let enforcer = CachedEnforcer::new(model, adapter).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        let enforcer = Arc::new(RwLock::new(enforcer));

        // Initialize default policies
        Self::initialize_default_policies(&enforcer).await?;

        Ok(Self { enforcer })
    }

    pub fn enforcer(&self) -> Arc<RwLock<CachedEnforcer>> {
        Arc::clone(&self.enforcer)
    }

    pub async fn check_permission(&self, subject: &str, object: &str, action: &str) -> bool {
        let enforcer = self.enforcer.read().await;
        enforcer.enforce((subject, object, action)).unwrap_or(false)
    }

    pub async fn add_policy(&self, policy: Vec<&str>) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut enforcer = self.enforcer.write().await;
        let policy_owned: Vec<String> = policy.into_iter().map(|s| s.to_string()).collect();
        enforcer.add_policy(policy_owned).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(())
    }

    async fn initialize_default_policies(enforcer: &Arc<RwLock<CachedEnforcer>>) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut enforcer_guard = enforcer.write().await;

        // Root role - superuser with access to everything
        enforcer_guard.add_policy(vec!["root".to_string(), "/api/*".to_string(), "*".to_string(), "allow".to_string()]).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Admin role inheritance - admin inherits user permissions
        enforcer_guard.add_grouping_policy(vec!["admin".to_string(), "user".to_string()]).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Admin can access ALL endpoints (allow)
        enforcer_guard.add_policy(vec!["admin".to_string(), "/api/*".to_string(), "*".to_string(), "allow".to_string()]).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Admin cannot access system endpoints (deny)
        enforcer_guard.add_policy(vec!["admin".to_string(), "/api/system/*".to_string(), "*".to_string(), "deny".to_string()]).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Users can access their own profile (allow)
        enforcer_guard.add_policy(vec!["user".to_string(), "/api/profile".to_string(), "read".to_string(), "allow".to_string()]).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Users can access health endpoints (allow)
        enforcer_guard.add_policy(vec!["user".to_string(), "/api/health".to_string(), "read".to_string(), "allow".to_string()]).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        enforcer_guard.add_policy(vec!["user".to_string(), "/api/health/detailed".to_string(), "read".to_string(), "allow".to_string()]).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        Ok(())
    }
}