# GraphQL Authorization Architecture

## Overview

This document outlines the authorization architecture for the GraphQL API, integrating **Casbin** for endpoint-level access control with **async-graphql field guards** for field-level permissions.

## Current Architecture

### Layered Authorization Model

```
┌─────────────────┐
│   Casbin        │ ← Endpoint Access Control
│   (Routes)      │   - Who can access /api/graphql
└─────────────────┘
         ↓
┌─────────────────┐
│ Field Guards    │ ← Field-Level Access Control
│ (GraphQL)       │   - What data they can see
└─────────────────┘
```

## Casbin Configuration

### Current Policies

```sql
-- Endpoint-level access control
p = user:.*:user, /api/graphql, POST, allow
p = user:.*:admin, /api/graphql, POST, allow
p = user:.*:root, /api/graphql, POST, allow

-- Existing REST API policies
p = user:.*:user, /profile, GET, allow
p = user:.*:admin, /profile, GET, allow
p = user:.*:root, /profile, GET, allow
```

### Casbin Model

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = regexMatch(r.sub, p.sub) && keyMatch(r.obj, p.obj) && regexMatch(r.act, r.act)
```

## GraphQL Field Guards

### Permission-Based Guards

```rust
use async_graphql::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use casbin::{CachedEnforcer, CoreApi};

pub struct PermissionGuard {
    pub permission: String,
}

impl PermissionGuard {
    pub fn new(permission: String) -> Self {
        Self { permission }
    }
}

#[async_trait::async_trait]
impl Guard for PermissionGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let context = ctx.data::<GraphQLContext>()?;

        if let Some(enforcer) = &context.casbin_enforcer {
            let user = context.require_auth()?;
            let subject = format!("user:{}:{}", user.id, user.role);

            if enforcer.read().await.enforce((&subject, &self.permission, "access"))? {
                Ok(())
            } else {
                Err(format!("Permission denied: {}", self.permission).into())
            }
        } else {
            Err("Authorization system unavailable".into())
        }
    }
}

// Convenience functions
pub fn permission_guard(permission: &str) -> PermissionGuard {
    PermissionGuard::new(permission.to_string())
}

pub fn admin_guard() -> PermissionGuard {
    PermissionGuard::new("admin:access".to_string())
}

pub fn owner_guard() -> PermissionGuard {
    PermissionGuard::new("owner:access".to_string())
}
```

### Role-Based Guards

```rust
pub struct RoleGuard {
    pub required_role: String,
}

impl RoleGuard {
    pub fn new(role: String) -> Self {
        Self { required_role: role }
    }
}

#[async_trait::async_trait]
impl Guard for RoleGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let context = ctx.data::<GraphQLContext>()?;
        let user = context.require_auth()?;

        if user.role == self.required_role || user.role == "root" {
            Ok(())
        } else {
            Err(format!("Role required: {}", self.required_role).into())
        }
    }
}

pub fn role_guard(role: &str) -> RoleGuard {
    RoleGuard::new(role.to_string())
}
```

## GraphQL Schema with Guards

### User Type with Field Guards

```rust
#[derive(SimpleObject)]
pub struct User {
    pub id: ID,
    pub username: String,
    pub email: String,

    // Public fields - no guard needed
    pub first_name: Option<String>,
    pub last_name: Option<String>,

    // Admin-only fields
    #[graphql(guard = "admin_guard()")]
    pub role: UserRole,

    #[graphql(guard = "admin_guard()")]
    pub is_active: bool,

    // Sensitive data - admin or owner
    #[graphql(guard = "permission_guard(\"users:read:sensitive\")")]
    pub created_at: String,

    #[graphql(guard = "permission_guard(\"users:read:sensitive\")")]
    pub updated_at: String,
}
```

### Query Guards

```rust
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get current authenticated user
    #[graphql(guard = "permission_guard(\"users:read\")")]
    async fn me(&self, ctx: &Context<'_>) -> Result<User> {
        let context = ctx.data::<GraphQLContext>()?;
        let user = context.require_auth()?;
        Ok(user.clone().into())
    }

    /// Get a user by ID (public profiles)
    #[graphql(guard = "permission_guard(\"users:read\")")]
    async fn user(&self, ctx: &Context<'_>, id: String) -> Result<Option<User>> {
        let context = ctx.data::<GraphQLContext>()?;
        let user_id = uuid::Uuid::parse_str(&id)
            .map_err(|_| async_graphql::Error::new("Invalid user ID"))?;

        match context.user_service.find_by_id(user_id).await {
            Ok(user) => {
                // Check if user can see this profile
                let current_user = context.require_auth()?;

                // Users can see their own profile and public profiles
                if current_user.id == user.id || context.has_role("admin") {
                    Ok(Some(user.into()))
                } else {
                    // Return limited public profile
                    Ok(Some(create_public_profile(user)))
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Get paginated list of users
    #[graphql(guard = "permission_guard(\"users:read\")")]
    async fn users(
        &self,
        ctx: &Context<'_>,
        pagination: PaginationInput,
        sorting: Vec<SortInput>,
        global_filter: Option<GlobalFilter>,
    ) -> Result<UserConnection> {
        let context = ctx.data::<GraphQLContext>()?;

        // Convert sorting to service parameters
        let sort_field = sorting.first().map(|s| s.field.clone());
        let sort_direction = sorting.first().map(|s| match s.direction {
            SortDirection::ASC => "ASC".to_string(),
            SortDirection::DESC => "DESC".to_string(),
        });
        let global_filter_value = global_filter.map(|f| f.value);

        // Get users based on permissions
        let (users, total_count) = if context.has_role("admin") {
            // Admins see all users
            context.user_service.get_users_paginated(
                pagination.page_index,
                pagination.page_size,
                sort_field,
                sort_direction,
                global_filter_value,
            ).await?
        } else {
            // Regular users see public profiles only
            context.user_service.get_public_users_paginated(
                pagination.page_index,
                pagination.page_size,
                sort_field,
                sort_direction,
                global_filter_value,
            ).await?
        };

        // Calculate pagination info
        let total_pages = (total_count as f64 / pagination.page_size as f64).ceil() as i32;
        let has_next_page = pagination.page_index + 1 < total_pages;
        let has_previous_page = pagination.page_index > 0;

        let page_info = PageInfo {
            has_next_page,
            has_previous_page,
            total_pages,
        };

        let items = users.into_iter().map(Into::into).collect();

        Ok(UserConnection {
            items,
            records_filtered: total_count,
            records_total: total_count,
            page_info,
        })
    }
}
```

### Mutation Guards

```rust
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Update current user's profile
    #[graphql(guard = "permission_guard(\"users:update\")")]
    async fn update_profile(
        &self,
        ctx: &Context<'_>,
        input: UpdateProfileInput,
    ) -> Result<User> {
        let context = ctx.data::<GraphQLContext>()?;
        let current_user = context.require_auth()?;

        // Users can only update their own profile
        context.user_service.update_user(current_user.id, input).await?;
        let updated_user = context.user_service.find_by_id(current_user.id).await?;

        Ok(updated_user.into())
    }

    /// Admin: Update any user
    #[graphql(guard = "admin_guard()")]
    async fn update_user(
        &self,
        ctx: &Context<'_>,
        id: ID,
        input: UpdateUserInput,
    ) -> Result<User> {
        let context = ctx.data::<GraphQLContext>()?;
        let user_id = uuid::Uuid::parse_str(&id)?;

        context.user_service.update_user(user_id, input).await?;
        let updated_user = context.user_service.find_by_id(user_id).await?;

        Ok(updated_user.into())
    }
}
```

## Permission Definitions

### Permission Matrix

| Permission | User | Admin | Root | Description |
|------------|------|-------|------|-------------|
| `users:read` | ✅ | ✅ | ✅ | Read user profiles |
| `users:read:sensitive` | ❌ | ✅ | ✅ | Read sensitive user data |
| `users:update` | ✅ (own) | ✅ | ✅ | Update user profiles |
| `users:create` | ❌ | ✅ | ✅ | Create new users |
| `users:delete` | ❌ | ❌ | ✅ | Delete users |
| `admin:access` | ❌ | ✅ | ✅ | Admin panel access |

### Ownership-Based Permissions

```rust
impl GraphQLContext {
    pub fn has_permission(&self, permission: &str) -> bool {
        if let Some(user) = &self.user {
            match (permission, user.role.as_str()) {
                // Admin permissions
                ("admin:access", "admin") | ("admin:access", "root") => true,

                // User permissions
                ("users:read", "user") | ("users:read", "admin") | ("users:read", "root") => true,
                ("users:read:sensitive", "admin") | ("users:read:sensitive", "root") => true,
                ("users:update", "user") | ("users:update", "admin") | ("users:update", "root") => true,
                ("users:create", "admin") | ("users:create", "root") => true,
                ("users:delete", "root") => true,

                // Ownership checks would be implemented here
                ("owner:access", _) => self.is_owner(),

                _ => false,
            }
        } else {
            false
        }
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.user.as_ref()
            .map(|u| u.role == role)
            .unwrap_or(false)
    }

    fn is_owner(&self) -> bool {
        // Implement ownership checking based on context
        // This would check if the current user owns the resource
        false // Placeholder
    }
}
```

## GraphQL Context

### Enhanced Context with Casbin

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use casbin::CachedEnforcer;

#[derive(Clone)]
pub struct GraphQLContext {
    pub user: Option<User>,
    pub user_service: UserService,
    pub casbin_enforcer: Option<Arc<RwLock<CachedEnforcer>>>,
}

impl GraphQLContext {
    pub fn require_auth(&self) -> Result<&User> {
        self.user.as_ref().ok_or_else(|| {
            async_graphql::Error::new("Authentication required")
        })
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.user.as_ref()
            .map(|u| u.role == role)
            .unwrap_or(false)
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        if let Some(enforcer) = &self.casbin_enforcer {
            if let Some(user) = &self.user {
                let subject = format!("user:{}:{}", user.id, user.role);
                // Note: This is synchronous for simplicity
                // In production, you might want async enforcement
                enforcer.try_read()
                    .map(|e| e.enforce((&subject, permission, "access")).unwrap_or(false))
                    .unwrap_or(false)
            } else {
                false
            }
        } else {
            // Fallback to role-based checking
            self.has_permission_fallback(permission)
        }
    }

    fn has_permission_fallback(&self, permission: &str) -> bool {
        if let Some(user) = &self.user {
            match (permission, user.role.as_str()) {
                ("users:read", "user") | ("users:read", "admin") | ("users:read", "root") => true,
                ("users:read:sensitive", "admin") | ("users:read:sensitive", "root") => true,
                ("admin:access", "admin") | ("admin:access", "root") => true,
                _ => false,
            }
        } else {
            false
        }
    }
}
```

## Implementation Steps

### Phase 1: Basic Guards
1. Add guard implementations
2. Apply guards to sensitive fields
3. Test with different user roles

### Phase 2: Casbin Integration
1. Add Casbin enforcer to GraphQL context
2. Create Casbin-based permission policies
3. Update guards to use Casbin

### Phase 3: Ownership Checks
1. Implement ownership validation
2. Add resource ownership tracking
3. Create ownership-based guards

### Phase 4: Advanced Features
1. Add query complexity limits
2. Implement rate limiting per user
3. Add audit logging for GraphQL operations

## Testing Strategy

### Permission Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_permissions() {
        let context = create_test_context("user");

        assert!(context.has_permission("users:read"));
        assert!(!context.has_permission("users:read:sensitive"));
        assert!(!context.has_permission("admin:access"));
    }

    #[tokio::test]
    async fn test_admin_permissions() {
        let context = create_test_context("admin");

        assert!(context.has_permission("users:read"));
        assert!(context.has_permission("users:read:sensitive"));
        assert!(context.has_permission("admin:access"));
    }
}
```

### GraphQL Testing

```graphql
# Test user permissions
query {
  me {
    id
    username
    email
    role  # Should fail for regular users
  }
}

# Test admin permissions
query {
  users {
    items {
      id
      username
      role  # Should work for admins
    }
  }
}
```

## Security Considerations

### Defense in Depth
1. **Casbin**: Endpoint-level access control
2. **Field Guards**: Field-level data protection
3. **Ownership**: Resource ownership validation
4. **Rate Limiting**: Query complexity protection

### Best Practices
1. **Principle of Least Privilege**: Grant minimal required permissions
2. **Fail-Safe Defaults**: Deny access by default
3. **Audit Logging**: Log all authorization decisions
4. **Regular Reviews**: Periodically review permission assignments

## Migration Strategy

### From Current System
1. **Keep Casbin** for endpoint access
2. **Add field guards** incrementally
3. **Test thoroughly** at each step
4. **Monitor performance** impact

### Future Enhancements
1. **Unified Permission System**: Single source of truth
2. **Dynamic Permissions**: Runtime permission evaluation
3. **Permission Inheritance**: Role hierarchy support
4. **Fine-grained Ownership**: Object-level permissions

This architecture provides **enterprise-grade authorization** with clean separation between endpoint and field-level access control, leveraging both Casbin and async-graphql's built-in features.