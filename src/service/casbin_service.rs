use casbin::{CachedEnforcer, CoreApi, DefaultModel, MgmtApi};
use sqlx_adapter::SqlxAdapter;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use crate::config::parameter;

pub struct CasbinService {
    pub enforcer: Arc<RwLock<CachedEnforcer>>,
}

impl CasbinService {
    pub async fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let database_url = parameter::get_or_panic("DATABASE_URL");

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

        // Debug logging
        info!("SECURITY: Casbin permission check - Subject: {}, Object: {}, Action: {}", subject, object, action);

        let result = enforcer.enforce((subject, object, action)).unwrap_or(false);
        info!("SECURITY: Casbin enforcement result: {}", result);

        result
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

        // Helper function to add policy only if it doesn't exist
        async fn add_policy_if_not_exists(
            enforcer: &mut CachedEnforcer,
            policy: Vec<String>,
        ) -> std::result::Result<(), Box<dyn std::error::Error>> {
            if enforcer.has_policy(policy.clone()) {
                info!("Policy already exists, skipping: {:?}", policy);
            } else {
                info!("Adding new policy: {:?}", policy);
                enforcer.add_policy(policy).await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            }
            Ok(())
        }



        // Root role - superuser with access to everything
        add_policy_if_not_exists(&mut enforcer_guard, vec!["root".to_string(), "/*".to_string(), "*".to_string(), "allow".to_string()]).await?;

        // User role policies - direct pattern matching for user subjects
        add_policy_if_not_exists(&mut enforcer_guard, vec!["user:.*:user".to_string(), "/profile".to_string(), "GET".to_string(), "allow".to_string()]).await?;
        add_policy_if_not_exists(&mut enforcer_guard, vec!["user:.*:user".to_string(), "/health".to_string(), "GET".to_string(), "allow".to_string()]).await?;
        add_policy_if_not_exists(&mut enforcer_guard, vec!["user:.*:user".to_string(), "/health/detailed".to_string(), "GET".to_string(), "allow".to_string()]).await?;

        // Admin role policies - admin users can access everything except system endpoints
        add_policy_if_not_exists(&mut enforcer_guard, vec!["user:.*:admin".to_string(), "/profile".to_string(), "GET".to_string(), "allow".to_string()]).await?;
        add_policy_if_not_exists(&mut enforcer_guard, vec!["user:.*:admin".to_string(), "/permissions/check".to_string(), "POST".to_string(), "allow".to_string()]).await?;
        add_policy_if_not_exists(&mut enforcer_guard, vec!["user:.*:admin".to_string(), "/system/.*".to_string(), ".*".to_string(), "deny".to_string()]).await?;

        // Root role policies - superuser with full access
        add_policy_if_not_exists(&mut enforcer_guard, vec!["user:.*:root".to_string(), "/profile".to_string(), "GET".to_string(), "allow".to_string()]).await?;
        add_policy_if_not_exists(&mut enforcer_guard, vec!["user:.*:root".to_string(), "/permissions/check".to_string(), "POST".to_string(), "allow".to_string()]).await?;

        Ok(())
    }
}