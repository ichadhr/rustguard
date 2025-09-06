# Authorization Architecture Plan

## Executive Summary

This document outlines the comprehensive authorization architecture plan, integrating Casbin for enterprise-grade access control across REST and GraphQL APIs with field-level permissions.

## Current Architecture Status

### ✅ **Implemented Components**

#### **Casbin Integration (✅ Official API Validated)**
- **Management API**: Policy CRUD operations (`add_policy`, `remove_policy`)
- **Core API**: Permission enforcement (`enforce`)
- **Database Persistence**: PostgreSQL adapter with policy storage
- **Subject Format**: `user:{id}:{role}` (e.g., `user:123:root`)
- **API Validation**: ✅ Confirmed using official Casbin Rust APIs

#### **REST API Authorization**
- **Endpoint Protection**: Route-level access control
- **Role-Based Access**: user, admin, root roles
- **Policy Examples**:
  ```sql
  p = user:.*:root, /*, *, allow
  p = user:.*:admin, /system/*, *, deny
  p = user:.*:user, /profile, GET, allow
  ```

#### **Error Handling**
- **Enhanced Authorization Errors**: Detailed error responses with error types
- **Validation Errors**: Consistent `details` field format
- **Security-Conscious**: Appropriate information disclosure

### 🔄 **In Development**

#### **GraphQL Integration Planning**
- **Field Guards**: async-graphql field-level permissions
- **Casbin Integration**: Reuse existing enforcer
- **Permission Matrix**: Granular access control

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐
│   REST API      │    │   GraphQL API   │
│                 │    │                 │
│ • Route Guards  │    │ • Field Guards  │
│ • Casbin        │────│ • Casbin        │
│ • RBAC          │    │ • Permissions   │
└─────────────────┘    └─────────────────┘
          │                       │
          └───────────────────────┘
                Casbin Core
            (Management + Core API)
```

## Casbin Configuration

### Current Model
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

### Subject Format Strategy
- **Format**: `user:{user_id}:{role}`
- **Examples**:
  - `user:123:root` (superuser)
  - `user:456:admin` (administrator)
  - `user:789:user` (regular user)
- **Benefits**: Hierarchical, extensible, regex-compatible

## Implementation Roadmap

### Phase 1: Foundation ✅ (Current)
- [x] Casbin Management + Core API integration
- [x] REST API endpoint protection
- [x] Role-based access control
- [x] Database persistence
- [x] Enhanced error responses

### Phase 2: GraphQL Integration 🔄 (Next)
- [ ] Add Casbin to GraphQL context
- [ ] Implement field guards
- [ ] Create permission-based guards
- [ ] Test with different user roles

### Phase 3: Advanced Features 🔄 (Future)
- [ ] Ownership-based permissions
- [ ] Dynamic permission evaluation
- [ ] Audit logging
- [ ] Performance monitoring

### Phase 4: Enterprise Features 🔄 (Future)
- [ ] ABAC (Attribute-Based Access Control)
- [ ] Permission inheritance
- [ ] Batch policy operations
- [ ] Real-time policy updates

## Permission Matrix

| Permission | User | Admin | Root | Description |
|------------|------|-------|------|-------------|
| `users:read` | ✅ | ✅ | ✅ | Read user profiles |
| `users:read:sensitive` | ❌ | ✅ | ✅ | Read sensitive data |
| `users:update` | ✅ (own) | ✅ | ✅ | Update profiles |
| `users:create` | ❌ | ✅ | ✅ | Create users |
| `users:delete` | ❌ | ❌ | ✅ | Delete users |
| `admin:access` | ❌ | ✅ | ✅ | Admin panel |
| `system:access` | ❌ | ❌ | ✅ | System endpoints |

## GraphQL Authorization Plan

### Field Guards Implementation
```rust
#[derive(SimpleObject)]
pub struct User {
    pub id: ID,
    pub username: String,

    // Public fields
    pub first_name: Option<String>,

    // Protected fields
    #[graphql(guard = "admin_guard()")]
    pub role: UserRole,

    #[graphql(guard = "permission_guard(\"users:read:sensitive\")")]
    pub created_at: String,
}
```

### Permission Guards
```rust
pub struct PermissionGuard {
    pub permission: String,
}

#[async_trait::async_trait]
impl Guard for PermissionGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        let context = ctx.data::<GraphQLContext>()?;
        let user = context.require_auth()?;

        if let Some(enforcer) = &context.casbin_enforcer {
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
```

## Security Considerations

### Defense in Depth
1. **Network Level**: Rate limiting, CORS
2. **Transport Level**: HTTPS enforcement
3. **Application Level**: Input validation, authentication
4. **Authorization Level**: Casbin RBAC + field guards
5. **Data Level**: Ownership checks, data filtering

### Best Practices
- **Principle of Least Privilege**: Minimal required permissions
- **Fail-Safe Defaults**: Deny by default
- **Regular Audits**: Permission review cycles
- **Security Monitoring**: Authorization failure logging

## Testing Strategy

### Unit Tests
```rust
#[tokio::test]
async fn test_permission_enforcement() {
    let enforcer = setup_test_enforcer().await;

    // Test user permissions
    assert!(enforce_permission(&enforcer, "user:123:user", "users:read", "access").await);
    assert!(!enforce_permission(&enforcer, "user:123:user", "admin:access", "access").await);

    // Test admin permissions
    assert!(enforce_permission(&enforcer, "user:456:admin", "admin:access", "access").await);
}
```

### Integration Tests
```rust
#[tokio::test]
async fn test_graphql_field_guards() {
    let schema = create_test_schema().await;
    let user_query = r#"
        query {
            me {
                id
                username
                role
            }
        }
    "#;

    // Test with regular user (should fail on role field)
    let result = schema.execute(user_query).await;
    assert!(result.errors.iter().any(|e| e.message.contains("Permission denied")));
}
```

## Performance Considerations

### Casbin Optimization
- **CachedEnforcer**: In-memory policy caching
- **Database Indexing**: Optimized policy queries
- **Connection Pooling**: Efficient database access
- **Async Operations**: Non-blocking enforcement

### Monitoring
- **Authorization Metrics**: Success/failure rates
- **Performance Monitoring**: Enforcement latency
- **Audit Logging**: Security event tracking
- **Policy Analytics**: Usage patterns

## Migration Strategy

### From Current System
1. **Maintain Compatibility**: Keep existing REST API authorization
2. **Gradual GraphQL Adoption**: Add field guards incrementally
3. **Unified Policy Management**: Single Casbin instance for both APIs
4. **Testing at Each Step**: Comprehensive test coverage

### Rollback Plan
- **Feature Flags**: Ability to disable GraphQL authorization
- **Fallback Permissions**: Role-based fallback if Casbin fails
- **Monitoring**: Alert on authorization failures

## Success Criteria

- [ ] **Security**: Zero unauthorized access in testing
- [ ] **Performance**: < 10ms authorization overhead
- [ ] **Compatibility**: REST and GraphQL authorization consistency
- [ ] **Maintainability**: Clear separation of concerns
- [ ] **Scalability**: Support for 1000+ concurrent users
- [ ] **Auditability**: Complete authorization event logging

## Future Enhancements

### Advanced Features
- **ABAC Integration**: Attribute-based access control
- **Real-time Policies**: Dynamic policy updates
- **Permission Inheritance**: Role hierarchy support
- **Fine-grained Ownership**: Object-level permissions

### Enterprise Features
- **Multi-tenancy**: Tenant-specific policies
- **Policy Versioning**: Audit trail for policy changes
- **Compliance Reporting**: GDPR/CCPA compliance features
- **Integration APIs**: Third-party authorization systems

This authorization architecture provides enterprise-grade security with clean separation between endpoint and field-level access control, leveraging Casbin's proven capabilities for scalable, maintainable authorization.

## References

### Official Casbin APIs
- **Management API**: https://raw.githubusercontent.com/casbin/casbin-rs/refs/heads/master/src/management_api.rs
- **RBAC API**: https://raw.githubusercontent.com/casbin/casbin-rs/refs/heads/master/src/rbac_api.rs
- **Casbin Documentation**: https://casbin.org/docs/overview

### Implementation Validation
- ✅ **Management + Core API**: Confirmed as optimal for web applications
- ✅ **PostgreSQL Adapter**: Official database persistence layer
- ✅ **Subject Format**: `user:{id}:{role}` compatible with regex matching
- ✅ **Policy Storage**: Database-backed with automatic synchronization