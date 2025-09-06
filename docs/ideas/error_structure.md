# Error Handling Architecture: Domain-Based & Relationship Errors

This document outlines the scalable error handling architecture for applications with multiple tables and complex relationships.

## Overview

As applications grow with more entities and relationships, error handling needs to scale accordingly. This architecture provides patterns for organizing errors by domain and handling relationship-specific scenarios.

## Current Error Structure

```
src/error/
├── authorization_error.rs  # Auth/permission errors
├── db_error.rs           # Database connection/query errors
├── request_error.rs      # Validation/parsing errors
├── token_error.rs        # Token-related errors
└── user_error.rs         # User-specific business errors
```

## Domain-Based Error Organization

### Recommended Structure

```
src/error/
├── auth/
│   ├── authorization_error.rs
│   ├── token_error.rs
│   └── mod.rs
├── data/
│   ├── entities/
│   │   ├── user_error.rs
│   │   ├── product_error.rs
│   │   └── order_error.rs
│   └── relationships/
│       ├── user_order_error.rs
│       ├── user_product_error.rs
│       └── mod.rs
├── infrastructure/
│   ├── db_error.rs
│   ├── cache_error.rs
│   └── mod.rs
└── api/
    ├── request_error.rs
    └── response_error.rs
```

### Benefits

- **Clear Separation**: Each domain owns its error types
- **Scalability**: Add new entities without affecting existing code
- **Team Organization**: Different teams can own different domains
- **Import Clarity**: Explicit error origins

## Relationship Error Patterns

### Foreign Key Violations

```rust
#[derive(Error, Debug)]
pub enum RelationshipError {
    #[error("Cannot delete user {user_id}: referenced by {count} orders")]
    UserHasOrders { user_id: String, count: i32 },

    #[error("User not found for order: {user_id}")]
    UserNotFound { user_id: String },

    #[error("Product not found in order: {product_id}")]
    ProductNotInOrder { product_id: String, order_id: String },

    #[error("Invalid relationship: {entity_a} cannot reference {entity_b}")]
    InvalidReference {
        entity_a: String,
        entity_b: String
    },
}
```

### Many-to-Many Relationship Errors

```rust
#[derive(Error, Debug)]
pub enum JoinTableError {
    #[error("User {user_id} already has role {role_id}")]
    DuplicateUserRole { user_id: String, role_id: String },

    #[error("Cannot remove last admin user {user_id}")]
    CannotRemoveLastAdmin { user_id: String },

    #[error("Circular dependency detected in {relationship}")]
    CircularDependency { relationship: String },
}
```

### Transaction-Level Errors

```rust
#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Transaction failed: {operation} on {entities}")]
    TransactionFailed {
        operation: String,
        entities: String
    },

    #[error("Partial update failure: {successful}/{total} operations completed")]
    PartialFailure {
        successful: i32,
        total: i32
    },

    #[error("Deadlock detected in transaction involving {tables}")]
    DeadlockDetected { tables: String },
}
```

## Composite Error Handling

### Unified Data Error

```rust
#[derive(Error, Debug)]
pub enum DataError {
    // Single entity errors
    #[error(transparent)]
    User(#[from] UserError),
    #[error(transparent)]
    Product(#[from] ProductError),
    #[error(transparent)]
    Order(#[from] OrderError),

    // Relationship errors
    #[error(transparent)]
    Relationship(#[from] RelationshipError),

    // Transaction errors
    #[error(transparent)]
    Transaction(#[from] TransactionError),
}
```

### Service Layer Error Handling

```rust
impl OrderService {
    pub async fn delete_order(&self, order_id: &str, user_id: &str) -> Result<(), DataError> {
        // Check if order exists and belongs to user
        let order = self.order_repo.find_by_id(order_id)
            .await?
            .ok_or_else(|| RelationshipError::OrderNotFound {
                order_id: order_id.to_string()
            })?;

        if order.user_id != user_id {
            return Err(RelationshipError::OrderOwnershipViolation {
                order_id: order_id.to_string()
            }.into());
        }

        // Check for related records
        let order_items = self.order_item_repo.find_by_order_id(order_id).await?;
        if !order_items.is_empty() {
            return Err(RelationshipError::OrderHasItems {
                order_id: order_id.to_string(),
                item_count: order_items.len() as i32
            }.into());
        }

        self.order_repo.delete(order_id).await?;
        Ok(())
    }
}
```

## Implementation Strategy

### Phase 1: Current Structure (Recommended)
Keep the current flat structure while your application is small:
- `user_error.rs` for user-specific errors
- `db_error.rs` for database errors
- Add relationship errors to existing files as needed

### Phase 2: Domain Separation
When you have 3+ entities, create domain folders:
```
src/error/
├── data/
│   ├── user_error.rs
│   ├── product_error.rs
│   └── relationship_error.rs
```

### Phase 3: Full Architecture
For large applications with complex relationships:
- Separate entity and relationship errors
- Implement error traits for consistency
- Use composite error types for service layers

## Error Response Format

All errors should follow the enhanced format:

```json
{
  "success": false,
  "message": "Access denied",
  "error": {
    "type": "AUTHORIZATION_ERROR",
    "details": "Insufficient permissions to access this resource"
  }
}
```

## Migration Path

1. **Start**: Keep current structure
2. **Grow**: Add relationship errors to existing files
3. **Scale**: Create domain folders when needed
4. **Mature**: Implement full architecture for large apps

## Best Practices

- **Consistent Naming**: Use `{Entity}Error` pattern
- **Error Composition**: Use `#[from]` for error conversion
- **Context Information**: Include entity IDs in error messages
- **HTTP Status Mapping**: Map errors to appropriate HTTP status codes
- **Documentation**: Document error scenarios for API consumers

This architecture provides a solid foundation that scales with your application's complexity while maintaining clean, maintainable error handling.