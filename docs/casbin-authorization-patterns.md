# Casbin Authorization Patterns Guide

## Overview

This document explains the Casbin authorization model patterns used in the Rust JWT Framework. It provides guidance for adding new roles and understanding the current authorization structure.

## Model Configuration

### Current Model (`src/casbin/model.conf`)

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = regexMatch(r.sub, p.sub) && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
```

### Component Explanation

- **Request Definition**: `sub, obj, act` (Subject, Object, Action)
- **Policy Definition**: `sub, obj, act, eft` (Subject, Object, Action, Effect)
- **Matchers**: How to match requests against policies
  - `regexMatch` for subject patterns (role-based)
  - `keyMatch` for object paths (hierarchical)
  - `regexMatch` for actions (HTTP methods)

## Subject Pattern Structure

### Format
```
user:{uuid}:{role}
```

### Examples
- `user:01991521-e61e-77c1-9562-10b38927acd1:user` (Regular user)
- `user:0199149a-dc95-70c3-860e-a2212e8e4ddd:admin` (Admin user)
- `user:019914c3-cea2-7a31-863f-d63cc411b003:root` (Root user)

### Policy Patterns
```rust
// User role pattern
"user:.*:user"

// Admin role pattern
"user:.*:admin"

// Root role pattern
"user:.*:root"

// Custom role pattern
"user:.*:moderator"
```

## Current Roles and Policies

### 1. User Role (`user:.*:user`)
**Permissions:**
- ✅ `GET /profile` - Access own profile
- ✅ `GET /health` - Health check endpoints
- ✅ `GET /health/detailed` - Detailed health check
- ❌ Admin endpoints (all denied)

### 2. Admin Role (`user:.*:admin`)
**Permissions:**
- ✅ `GET /profile` - Access own profile
- ✅ `POST /permissions/check` - Check permissions
- ✅ All other endpoints (wildcard allow)
- ❌ `/system/*` endpoints (explicit deny)

### 3. Root Role (`user:.*:root`)
**Permissions:**
- ✅ All endpoints (wildcard allow)
- ✅ `GET /profile` - Access own profile
- ✅ `POST /permissions/check` - Check permissions

### 4. Root User (`root`)
**Permissions:**
- ✅ All endpoints (wildcard allow)

## Adding New Roles

### Step 1: Define Role Pattern
```rust
// In src/service/casbin_service.rs
let moderator_pattern = "user:.*:moderator";
```

### Step 2: Add Role Policies
```rust
// Add policies for the new role
add_policy_if_not_exists(&mut enforcer_guard, vec![
    moderator_pattern.to_string(),
    "/profile".to_string(),
    "GET".to_string(),
    "allow".to_string()
]).await?;

add_policy_if_not_exists(&mut enforcer_guard, vec![
    moderator_pattern.to_string(),
    "/posts".to_string(),
    ".*".to_string(),  // All actions on posts
    "allow".to_string()
]).await?;

add_policy_if_not_exists(&mut enforcer_guard, vec![
    moderator_pattern.to_string(),
    "/admin/users".to_string(),
    "GET".to_string(),  // Can view users but not modify
    "allow".to_string()
]).await?;
```

### Step 3: Update User Registration
```rust
// In user registration logic
enum UserRole {
    User,
    Admin,
    Root,
    Moderator,  // Add new role
}
```

### Step 4: Test New Role
```bash
# Test moderator permissions
POST /api/auth/login
{
  "email": "moderator@example.com",
  "password": "Mod123!"
}

# Should allow:
GET /api/profile
GET /api/posts
GET /api/admin/users

# Should deny:
POST /api/admin/users
DELETE /api/posts
```

## Object Path Patterns

### Current Path Structure
```
/                     # Root
├── /profile          # User profiles
├── /health           # Health checks
├── /health/detailed  # Detailed health
├── /permissions/check # Permission checking
├── /system/*         # System endpoints (admin denied)
└── /*                # All other endpoints
```

### Path Matching Rules
- **Exact Match**: `/profile` matches exactly `/profile`
- **Wildcard**: `/*` matches `/anything`
- **Hierarchical**: `/system/*` matches `/system/status`, `/system/config`

## Action Patterns

### HTTP Methods
```rust
// Allow all actions
".*"

// Specific actions
"GET"
"POST"
"PUT"
"DELETE"

// Multiple actions (regex)
"(GET|POST)"
```

## Best Practices

### 1. Role Hierarchy
- Use consistent naming: `user:.*:{role}`
- Keep roles simple and clear
- Document role capabilities

### 2. Permission Design
- **Principle of Least Privilege**: Give minimum required permissions
- **Explicit Deny**: Use deny rules for sensitive operations
- **Wildcard Usage**: Use `/*` sparingly, prefer specific paths

### 3. Policy Organization
```rust
// Group related permissions
// 1. Basic user permissions
add_policy_if_not_exists(&mut enforcer_guard, vec![
    role_pattern, "/profile", "GET", "allow"
]).await?;

// 2. Role-specific permissions
add_policy_if_not_exists(&mut enforcer_guard, vec![
    role_pattern, "/admin/users", "GET", "allow"
]).await?;

// 3. Deny rules (if needed)
add_policy_if_not_exists(&mut enforcer_guard, vec![
    role_pattern, "/system/*", "*", "deny"
]).await?;
```

### 4. Testing New Roles
```rust
// Test cases for new roles
#[cfg(test)]
mod tests {
    #[test]
    fn test_moderator_permissions() {
        // Test allowed actions
        assert!(check_permission("user:uuid:moderator", "/profile", "GET"));

        // Test denied actions
        assert!(!check_permission("user:uuid:moderator", "/admin/users", "DELETE"));
    }
}
```

## Common Patterns

### Read-Only Role
```rust
let readonly_pattern = "user:.*:viewer";

add_policy_if_not_exists(&mut enforcer_guard, vec![
    readonly_pattern.to_string(),
    "/.*".to_string(),
    "GET".to_string(),
    "allow".to_string()
]).await?;
```

### Content Creator Role
```rust
let creator_pattern = "user:.*:creator";

add_policy_if_not_exists(&mut enforcer_guard, vec![
    creator_pattern.to_string(),
    "/content".to_string(),
    "(POST|PUT|DELETE)".to_string(),
    "allow".to_string()
]).await?;
```

### API Access Role
```rust
let api_pattern = "user:.*:api";

add_policy_if_not_exists(&mut enforcer_guard, vec![
    api_pattern.to_string(),
    "/api/.*".to_string(),
    ".*".to_string(),
    "allow".to_string()
]).await?;
```

## Troubleshooting

### Common Issues

1. **Role not matching**: Check regex pattern syntax
2. **Path not matching**: Verify path structure and wildcards
3. **Unexpected deny**: Check for conflicting deny rules
4. **Permission inheritance**: Ensure role hierarchy is correct

### Debug Commands
```rust
// Check if policy exists
enforcer.has_policy(vec!["user:.*:admin", "/profile", "GET", "allow"])

// Test enforcement
enforcer.enforce(("user:uuid:admin", "/profile", "GET"))

// List all policies
enforcer.get_policy()
```

## Maintenance

### Regular Tasks
1. **Audit permissions**: Review role capabilities quarterly
2. **Update patterns**: Modify regex patterns as needed
3. **Test coverage**: Ensure new endpoints have proper policies
4. **Documentation**: Keep this guide updated with new roles

### Performance Considerations
- Regex patterns are evaluated on each request
- Keep patterns simple and efficient
- Use specific paths over wildcards when possible
- Cache policy decisions when appropriate

## Examples

### Adding a "Manager" Role
```rust
// 1. Define pattern
let manager_pattern = "user:.*:manager";

// 2. Add policies
add_policy_if_not_exists(&mut enforcer_guard, vec![
    manager_pattern.to_string(),
    "/profile".to_string(),
    "GET".to_string(),
    "allow".to_string()
]).await?;

add_policy_if_not_exists(&mut enforcer_guard, vec![
    manager_pattern.to_string(),
    "/team".to_string(),
    ".*".to_string(),
    "allow".to_string()
]).await?;

add_policy_if_not_exists(&mut enforcer_guard, vec![
    manager_pattern.to_string(),
    "/reports".to_string(),
    "GET".to_string(),
    "allow".to_string()
]).await?;
```

### Testing the New Role
```bash
# Login as manager
POST /api/auth
{
  "email": "manager@example.com",
  "password": "Manager123!"
}

# Test permissions
GET /api/profile          # ✅ Should work
GET /api/team             # ✅ Should work
POST /api/team            # ✅ Should work
GET /api/reports          # ✅ Should work
POST /api/admin/users     # ❌ Should be denied
```

This pattern ensures consistent, maintainable authorization rules that are easy to extend and modify.