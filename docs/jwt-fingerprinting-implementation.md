# JWT Fingerprinting Implementation Plan

## Overview
This document outlines the implementation of JWT fingerprinting to enhance security and prevent token sidejacking attacks, following OWASP guidelines.

## Current Database Analysis

### Users Table Structure
```sql
-- Current users table (from database inspection)
CREATE TABLE users (
    id UUID PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255),
    password VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    refresh_token_hash VARCHAR(255),
    refresh_token_expires_at TIMESTAMPTZ,
    refresh_token_family VARCHAR(100)
);
```

## Implementation Options

### Option 1: Extend Users Table (Recommended)
Add fingerprint fields directly to the existing users table:

```sql
ALTER TABLE users ADD COLUMN current_fingerprint_hash VARCHAR(64);
ALTER TABLE users ADD COLUMN fingerprint_created_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE users ADD COLUMN fingerprint_expires_at TIMESTAMPTZ;
```

**Pros:**
- Simple schema change
- Leverages existing table structure
- Easy to implement and maintain

**Cons:**
- Only one active fingerprint per user
- No historical tracking

### Option 2: Separate Fingerprints Table
Create a dedicated table for fingerprint management:

```sql
CREATE TABLE user_fingerprints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint_hash VARCHAR(64) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    device_fingerprint TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX user_fingerprints_user_id_idx ON user_fingerprints(user_id);
CREATE INDEX user_fingerprints_fingerprint_hash_idx ON user_fingerprints(fingerprint_hash);
CREATE INDEX user_fingerprints_active_idx ON user_fingerprints(user_id, is_active);
```

**Pros:**
- Multiple active fingerprints per user
- Historical tracking
- Device-specific information
- Better audit trail

**Cons:**
- More complex implementation
- Additional database queries

## Recommended Implementation: Option 2 (Separate Fingerprints Table)

### Database Migration
```sql
-- Create separate fingerprints table
CREATE TABLE user_fingerprints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint_hash VARCHAR(64) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMPTZ
);

-- Optimized indexes
CREATE INDEX user_fingerprints_user_id_idx ON user_fingerprints(user_id);
CREATE INDEX user_fingerprints_fingerprint_hash_idx ON user_fingerprints(fingerprint_hash);
CREATE INDEX user_fingerprints_active_idx ON user_fingerprints(user_id, is_active);
CREATE INDEX user_fingerprints_expires_at_idx ON user_fingerprints(expires_at) WHERE is_active = true;
```

### Implementation Architecture

#### 1. Fingerprint Generation Flow
```
Client Login Request
    ↓
Generate Random Fingerprint (32 bytes)
    ↓
Store as HttpOnly Cookie: user_fingerprint
    ↓
Hash with SHA256: fingerprint_hash
    ↓
Update users.current_fingerprint_hash
    ↓
Include fingerprint_hash in JWT Claims
    ↓
Return JWT to Client
```

#### 2. Request Validation Flow
```
Incoming Authenticated Request
    ↓
Extract JWT from Authorization Header
    ↓
Extract fingerprint from HttpOnly Cookie
    ↓
Hash cookie fingerprint with SHA256
    ↓
Query database: user_fingerprints table
    ↓
Find active fingerprint matching hash and user
    ↓
Validate JWT claims match database record
    ↓
Allow/Deny Request
```

### Code Changes Required

#### 1. Update TokenClaimsDto
```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenClaimsDto {
    pub sub: Uuid,
    pub email: String,
    pub iat: i64,
    pub exp: i64,
    pub fingerprint_hash: String,  // SHA256 hash of fingerprint
}
```

#### 2. Create Fingerprint Entity
```rust
#[derive(Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct UserFingerprint {
    pub id: Uuid,
    pub user_id: Uuid,
    pub fingerprint_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub last_used_at: Option<DateTime<Utc>>,
}
```

#### 3. Fingerprint Service
```rust
pub struct FingerprintService;

impl FingerprintService {
    pub fn generate_fingerprint() -> String {
        // Generate 32 random bytes, base64 encode
    }

    pub fn hash_fingerprint(fingerprint: &str) -> String {
        // SHA256 hash of fingerprint
    }

    pub fn create_cookie(fingerprint: &str) -> Cookie {
        // Create HttpOnly, Secure, SameSite cookie
    }
}
```

#### 4. Updated Auth Handler
```rust
pub async fn auth(
    State(state): State<AuthState>,
    ValidatedRequest(payload): ValidatedRequest<UserLoginDto>,
    req: HttpRequest, // Add request parameter to extract client info
) -> Result<Json<TokenReadDto>, ApiError> {
    // ... existing auth logic ...

    // Generate fingerprint
    let fingerprint = FingerprintService::generate_fingerprint();
    let fingerprint_hash = FingerprintService::hash_fingerprint(&fingerprint);

    // Extract client information for security tracking
    let ip_address = req
        .headers()
        .get("x-forwarded-for")
        .or_else(|| req.headers().get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.peer_addr().map(|addr| addr.ip().to_string()));

    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Create fingerprint record in database with client info
    state.fingerprint_repo.create_fingerprint(
        user.id,
        &fingerprint_hash,
        ip_address,
        user_agent,
    )?;

    // Create JWT with fingerprint
    let token = state.token_service.generate_token_with_fingerprint(user, &fingerprint_hash)?;

    // Set fingerprint cookie
    let cookie = FingerprintService::create_cookie(&fingerprint);

    Ok(Json(token).with_cookie(cookie))
}
```

#### 5. Updated Auth Middleware
```rust
pub async fn auth(
    State(state): State<TokenState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    // Extract JWT
    let token_data = extract_and_validate_jwt(&req)?;

    // Extract fingerprint from cookie
    let cookie_fingerprint = extract_fingerprint_cookie(&req)?;

    // Hash the cookie fingerprint
    let cookie_hash = FingerprintService::hash_fingerprint(&cookie_fingerprint);

    // Validate against JWT claims
    if cookie_hash != token_data.claims.fingerprint_hash {
        return Err(TokenError::InvalidFingerprint)?;
    }

    // Validate against database - find active fingerprint for user
    let fingerprint = state.fingerprint_repo.find_active_fingerprint(
        token_data.claims.sub,
        &cookie_hash
    )?;

    if fingerprint.is_none() {
        return Err(TokenError::InvalidFingerprint)?;
    }

    // Update last_used_at for analytics
    if let Some(fp) = fingerprint {
        state.fingerprint_repo.update_last_used(fp.id).await?;
    }

    // Get user and continue with request
    let user = state.user_repo.find(token_data.claims.sub)?;
    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}
```

### Security Benefits

1. **Prevents Token Replay Attacks**: Stolen JWTs can't be used without the matching HttpOnly cookie
2. **Device-Specific Sessions**: Each browser/device gets a unique fingerprint
3. **Database Validation**: Server-side verification ensures integrity
4. **Automatic Expiration**: Fingerprints can be set to expire
5. **OWASP Compliant**: Follows JWT security best practices

### API Response Changes

#### Authentication Success Response
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "iat": 1640995200,
  "exp": 1640998800
}
```
*Note: The response format remains the same; fingerprinting is handled via cookies*

#### JWT Claims (Internal)
```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "iat": 1640995200,
  "exp": 1640998800,
  "fingerprint_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### Cookie Configuration
- **Name**: `user_fingerprint`
- **Value**: Base64-encoded 32-byte random string
- **Flags**: `HttpOnly`, `Secure`, `SameSite=Strict`
- **Max-Age**: 30 days (configurable)
- **Path**: `/`

### Error Handling

#### New Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    // ... existing errors ...
    #[error("Invalid fingerprint")]
    InvalidFingerprint,
    #[error("Fingerprint expired")]
    FingerprintExpired,
    #[error("Missing fingerprint cookie")]
    MissingFingerprintCookie,
}
```

### Migration Strategy

1. **Deploy Database Migration**: Add fingerprint columns to users table
2. **Update Application Code**: Implement fingerprinting logic
3. **Gradual Rollout**: New logins get fingerprints; existing sessions remain valid
4. **Cleanup**: Remove expired fingerprints periodically

### Testing Strategy

#### Unit Tests
- Fingerprint generation and hashing
- Cookie creation and validation
- JWT claims validation

#### Integration Tests
- Full authentication flow with fingerprinting
- Cookie handling
- Database fingerprint storage/retrieval

#### Security Tests
- Token replay attack prevention
- Cookie theft simulation
- Cross-device validation

### Monitoring and Logging

#### Fingerprint Events to Log
- Fingerprint generation
- Fingerprint validation failures
- Fingerprint expiration
- Cookie validation errors

#### Metrics to Track
- Authentication success/failure rates
- Fingerprint validation failure rates
- Average fingerprint lifetime

## Automated Cleanup

**Implementation**: Use Docker containers with internal cron for automated cleanup of expired fingerprints.

**Benefits**:
- Self-contained cleanup processes
- No external dependencies
- Easy scaling and deployment
- Built-in logging and monitoring

**See**: `docs/docker/docker-setup.md` and `docs/docker/docker-cleanup.md` for detailed Docker cleanup implementation.