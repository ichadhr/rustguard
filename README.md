# Rust JWT Fingerprinting Framework

A secure, production-ready web framework built with Rust, featuring JWT authentication with device fingerprinting for enhanced security against token theft.

## Features

### Core Security Features
- **JWT Authentication** with configurable expiration
- **Device Fingerprinting** - Each login generates a unique device fingerprint
- **HttpOnly Cookies** - Fingerprint stored securely in HttpOnly cookies
- **Session Binding** - JWT tokens are bound to specific device sessions
- **Automatic Cleanup** - Expired fingerprints are cleaned up periodically
- **RBAC Authorization** - Role-Based Access Control with Casbin
- **Admin Policy Management** - Admin-only endpoints for policy management
- **Database-Backed Policies** - Persistent authorization rules in PostgreSQL

### Framework Features
- **Axum Web Framework** - High-performance async web framework
- **PostgreSQL Database** - Robust data persistence with SQLx
- **Structured Logging** - Comprehensive logging with tracing
- **Graceful Shutdown** - Proper cleanup on application termination
- **Input Validation** - Request validation with the validator crate
- **Error Handling** - Comprehensive error handling with thiserror
- **Password Security** - bcrypt hashing with configurable cost factor

### Security Benefits
- **Token Theft Protection** - Stolen JWTs cannot be used without matching fingerprint
- **Cross-Device Security** - Different devices get different fingerprints
- **Session Expiration** - Automatic fingerprint cleanup prevents accumulation
- **IP Tracking** - Optional IP address logging for security monitoring

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTTP Request  │───▶│   Middleware    │───▶│   Handlers      │
│                 │    │   (Auth)        │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Fingerprint    │    │   Services      │    │   Repository    │
│   Service       │◀──▶│                 │◀──▶│                 │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ In-Memory Store │    │   Database      │    │   JWT Token     │
│                 │    │   (PostgreSQL)  │    │   Service       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Prerequisites

- Rust 1.70 or higher
- PostgreSQL 12 or higher
- Linux/Windows/macOS

## Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd rust-jwt-framework
```

### 2. Environment Setup
```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Database Setup
```bash
# Install SQLx CLI if not already installed
cargo install sqlx-cli

# Run database migrations
sqlx migrate run
```

### 4. Build and Run
```bash
cargo build --release
cargo run --release
```

The server will start on `http://localhost:8081`

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection string | - | Yes |
| `JWT_SECRET` | Secret key for JWT signing | - | Yes |
| `JWT_TTL_IN_MINUTES` | JWT token expiration time | 30 | No |
| `SERVER_ADDRESS` | Server bind address | 127.0.0.1 | No |
| `SERVER_PORT` | Server port | 8081 | No |

### Example .env file
```env
DATABASE_URL=postgresql://username:password@localhost:5432/framework_db
JWT_SECRET=your-super-secret-jwt-key-here
JWT_TTL_IN_MINUTES=60
SERVER_ADDRESS=0.0.0.0
SERVER_PORT=8081
```

## API Documentation

### Authentication Endpoints

#### POST /api/auth
Authenticate user and receive JWT token with fingerprint cookie.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "iat": 1640995200,
  "exp": 1640998800
}
```

**Security Notes:**
- Sets HttpOnly cookie: `user_fingerprint=<fingerprint>`
- JWT contains fingerprint hash for validation
- Cookie expires in 30 days

#### POST /api/register
Register a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "password123",
  "username": "johndoe",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:**
```json
{
  "data": {
    "id": "uuid-here",
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "is_active": true,
    "created_at": "2023-01-01T00:00:00Z",
    "updated_at": "2023-01-01T00:00:00Z"
  }
}
```

#### GET /api/profile
Get authenticated user profile.

**Headers:**
```
Authorization: Bearer <jwt-token>
Cookie: user_fingerprint=<fingerprint>
```

**Response:**
```json
{
  "data": {
    "id": "uuid-here",
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "role": "user",
    "is_active": true,
    "created_at": "2023-01-01T00:00:00Z",
    "updated_at": "2023-01-01T00:00:00Z"
  }
}
```

#### GET /api/health
Health check endpoint.

**Response:**
```
Healthy...
```

## Security Features

### JWT Fingerprinting
1. **Login Process:**
   - User provides credentials
   - Server validates credentials
   - Server generates cryptographically secure fingerprint
   - Fingerprint hash is embedded in JWT
   - Raw fingerprint is stored in HttpOnly cookie

2. **Authentication Process:**
   - Client sends JWT in Authorization header
   - Client sends fingerprint cookie automatically
   - Server validates JWT signature and claims
   - Server hashes received fingerprint
   - Server compares hash with JWT fingerprint hash
   - Server validates fingerprint against in-memory store

3. **Security Benefits:**
   - **Token Theft Protection:** Stolen JWTs are useless without matching cookie
   - **Cross-Device Security:** Each device gets unique fingerprint
   - **Session Isolation:** Different browser sessions are isolated
   - **Automatic Expiration:** Fingerprints expire and are cleaned up

### Refresh Token System with Family Tracking

The framework implements a comprehensive refresh token system that enhances security and provides better session management through token families.

#### Architecture Overview

```mermaid
graph TD
    A[Client Login] --> B[Generate Tokens]
    B --> C[Store Refresh Token in DB]
    C --> D[Return Access + Refresh Tokens]

    E[Client Request] --> F[Validate Access Token]
    F --> G{Token Valid?}
    G -->|Yes| H[Process Request]
    G -->|No| I[Client Calls /refresh]

    I --> J[Validate Refresh Token]
    J --> K{Valid?}
    K -->|Yes| L[Generate New Access Token]
    K -->|No| M[Return 401 Unauthorized]

    L --> N{Token Rotation?}
    N -->|Yes| O[Generate New Refresh Token]
    N -->|No| P[Keep Same Refresh Token]
    O --> Q[Update DB with New Token]
    P --> Q
    Q --> R[Return New Access Token]

    S[Client Logout] --> T{Logout Type}
    T -->|Single Session| U[Invalidate One Token]
    T -->|All Sessions| V[Invalidate Family]
```

#### Token Flow with Families

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Auth Server
    participant DB as Database

    Note over C,DB: Initial Login
    C->>A: POST /auth (credentials)
    A->>A: Generate family_id = UUID
    A->>A: Generate refresh_token
    A->>DB: Store: user_id, hash(refresh_token), family_id, expires_at
    A->>C: Return access_token + refresh_token

    Note over C,DB: Token Refresh
    C->>A: POST /refresh (refresh_token)
    A->>DB: Validate refresh_token exists and not expired
    A->>A: Generate new_access_token
    A->>A: Option: Generate new_refresh_token with same family_id
    A->>DB: Update last_used_at, optionally new token hash
    A->>C: Return new_access_token (+ new_refresh_token if rotated)

    Note over C,DB: Family Logout
    C->>A: POST /logout?family=true
    A->>DB: Invalidate all tokens with matching family_id
    A->>C: Success response
```

#### Key Security Features

1. **Token Families**: Group related tokens for bulk operations
2. **Token Rotation**: Optional rotation on refresh for enhanced security
3. **Database Storage**: Secure storage with hash-only approach
4. **Family-Based Logout**: Invalidate single sessions or entire families
5. **Automatic Expiration**: Configurable token lifetimes
6. **Integration**: Works seamlessly with existing fingerprinting

#### API Endpoints

##### POST /api/refresh
Exchange refresh token for new access token.

**Request:**
```json
{
  "refresh_token": "refresh_token_here"
}
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "iat": 1640995200,
  "exp": 1640998800,
  "refresh_token": "new_refresh_token_here" // if rotation enabled
}
```

##### POST /api/logout
Invalidate refresh tokens.

**Request:**
```json
{
  "refresh_token": "refresh_token_here",
  "logout_family": true // optional: logout all family tokens
}
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

#### Enhanced Login Response

The login endpoint now returns both access and refresh tokens:

**POST /api/auth Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "iat": 1640995200,
  "exp": 1640998800,
  "refresh_token": "refresh_token_here",
  "family_id": "uuid-family-id"
}
```

#### Configuration Options

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `REFRESH_TOKEN_TTL_DAYS` | Refresh token expiration in days | 30 | No |
| `REFRESH_TOKEN_ROTATION` | Enable token rotation on refresh | true | No |
| `REFRESH_TOKEN_FAMILY_LOGOUT` | Enable family-based logout | true | No |

#### Security Benefits

- **Enhanced Session Control**: Granular logout options (single session vs all sessions)
- **Token Rotation**: Prevents replay attacks by rotating tokens on refresh
- **Family Tracking**: Better audit trail and session management
- **Backward Compatibility**: Existing JWT-only flows continue to work
- **Database Security**: Only token hashes stored, never plain tokens

## Authorization System (Casbin RBAC)

The framework implements **Role-Based Access Control (RBAC)** using Casbin, providing enterprise-grade authorization with database persistence and programmatic policy management.

### Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTTP Request  │───▶│   Middleware    │───▶│   Handlers      │
│                 │    │   (Auth + RBAC) │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Casbin Service  │    │   Policies      │    │ Admin Endpoints │
│   (Business     │◀──▶│   (Database)    │◀──▶│   (Management)  │
│    Logic)       │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Key Features

- **RBAC Model**: Subject (user/role) → Object (resource) → Action (permission)
- **Database Persistence**: Policies stored in PostgreSQL `casbin_rule` table
- **Admin-Only Management**: Secure policy management endpoints
- **Automatic Enforcement**: Middleware automatically checks permissions
- **Service Pattern**: Clean architecture with dependency injection
- **Audit Logging**: Admin actions are logged for security

### RBAC Model Configuration

The system uses a standard RBAC model defined in `src/casbin/model.conf`:

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

### API Endpoints

#### Admin-Only Policy Management

##### POST /api/admin/policies
Add new authorization policies (Admin users only).

**Headers:**
```
Authorization: Bearer <admin-jwt>
Cookie: user_fingerprint=<fingerprint>
```

**Request:**
```json
{
  "subject": "admin",
  "object": "/api/admin/*",
  "action": "*"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Policy added: admin can * on /api/admin/* (by admin: admin@example.com)",
  "data": {
    "success": true,
    "message": "Policy added: admin can * on /api/admin/* (by admin: admin@example.com)"
  }
}
```

##### POST /api/admin/permissions/check
Check if a subject has permission for an action on an object (Admin users only).

**Request:**
```json
{
  "subject": "user:123",
  "object": "/api/profile",
  "action": "read"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Permission check completed by admin: admin@example.com",
  "data": {
    "allowed": true,
    "subject": "user:123",
    "object": "/api/profile",
    "action": "read"
  }
}
```

### Usage Examples

#### 1. Add Admin Policies
```bash
curl -X POST http://localhost:8081/api/admin/policies \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -H "Cookie: user_fingerprint=abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "admin",
    "object": "/api/admin/*",
    "action": "*"
  }'
```

#### 2. Check User Permissions
```bash
curl -X POST http://localhost:8081/api/admin/permissions/check \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -H "Cookie: user_fingerprint=abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:123",
    "object": "/api/profile",
    "action": "read"
  }'
```

#### 3. Access Protected Routes
```bash
# These routes automatically enforce Casbin policies
curl http://localhost:8081/api/profile \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -H "Cookie: user_fingerprint=abc123..."
```

### Security Benefits

1. **Granular Access Control**: Define exactly what each user/role can do
2. **Admin-Only Management**: Only administrators can modify policies
3. **Database Persistence**: Policies survive application restarts
4. **Audit Trail**: All policy changes are logged
5. **Automatic Enforcement**: No manual permission checks needed
6. **Scalable**: Supports complex role hierarchies and permissions

### Database Schema

Policies are stored in the `casbin_rule` table:

```sql
CREATE TABLE casbin_rule (
    id SERIAL PRIMARY KEY,
    ptype VARCHAR NOT NULL,        -- Policy type (p, g, etc.)
    v0 VARCHAR NOT NULL,           -- Subject (user, role, etc.)
    v1 VARCHAR NOT NULL,           -- Object (resource, endpoint)
    v2 VARCHAR NOT NULL,           -- Action (read, write, delete)
    v3 VARCHAR NOT NULL,           -- Additional parameters
    v4 VARCHAR NOT NULL,
    v5 VARCHAR NOT NULL,
    CONSTRAINT unique_key_sqlx_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
);
```

### Configuration

The authorization system uses your existing configuration system:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | PostgreSQL connection (used for policies) | - | Yes |

### Integration with Existing Security

The authorization system integrates seamlessly with existing security features:

- **JWT Authentication**: Provides user context for authorization
- **Device Fingerprinting**: Ensures session integrity
- **Rate Limiting**: Protects against abuse
- **Audit Logging**: Tracks all authorization decisions

### Policy Examples

```bash
# Admin can do everything on admin endpoints
curl -X POST /api/admin/policies -d '{"subject":"admin","object":"/api/admin/*","action":"*"}'

# Users can read their own profile
curl -X POST /api/admin/policies -d '{"subject":"user","object":"/api/profile","action":"read"}'

# Moderators can edit posts
curl -X POST /api/admin/policies -d '{"subject":"moderator","object":"/api/posts","action":"edit"}'

# Assign user to admin role
curl -X POST /api/admin/policies -d '{"subject":"user:123","object":"admin","action":""}'
```

### Password Security
- **bcrypt hashing** with cost factor 12 (production-ready)
- **No plaintext storage** of passwords
- **Secure comparison** using constant-time algorithms

### Additional Security
- **Input validation** on all endpoints
- **SQL injection protection** via prepared statements
- **XSS protection** via proper content-type handling
- **CSRF protection** via HttpOnly cookies

## Testing

### Running Tests
```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Integration Testing
Use the provided `test.http` file with VS Code REST Client or similar tools:

```bash
# Install REST Client extension in VS Code
# Open test.http and run requests in order
```

### Test Scenarios Covered
- ✅ Normal authentication flow
- ✅ Invalid credentials handling
- ✅ Missing fingerprint cookie
- ✅ Invalid fingerprint validation
- ✅ Token expiration
- ✅ Cross-device access prevention
- ✅ Fingerprint expiration
- ✅ Input validation
- ✅ Error handling

## 📊 Monitoring & Observability

### Logging
The application uses structured logging with the following levels:
- **ERROR:** Critical errors that need immediate attention
- **WARN:** Warning conditions that should be reviewed
- **INFO:** General information about application operation
- **DEBUG:** Detailed debugging information
- **TRACE:** Very detailed tracing information

### Health Checks
- **GET /api/health** - Basic health check endpoint
- Returns "Healthy..." when service is operational

### Metrics (Future Enhancement)
- Request count and latency
- Authentication success/failure rates
- Database connection pool status
- Memory usage statistics

## Deployment

### Docker Deployment
```dockerfile
FROM rust:1.70-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates
COPY --from=builder /app/target/release/framework /usr/local/bin/
EXPOSE 8081
CMD ["framework"]
```

### Systemd Service
```ini
[Unit]
Description=Rust JWT Framework
After=network.target postgresql.service

[Service]
Type=simple
User=framework
ExecStart=/usr/local/bin/framework
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Production Checklist
- [ ] Set strong `JWT_SECRET` (32+ characters)
- [ ] Use production PostgreSQL instance
- [ ] Configure proper logging levels
- [ ] Set up monitoring and alerting
- [ ] Configure firewall rules
- [ ] Set up SSL/TLS certificates
- [ ] Configure backup strategies
- [ ] Set up log rotation

## Development

### Code Organization
```
src/
├── main.rs              # Application entry point
├── config/              # Configuration management
├── entity/              # Database entities
├── dto/                 # Data transfer objects
├── service/             # Business logic
├── repository/          # Data access layer
├── handler/             # HTTP request handlers
├── middleware/          # HTTP middleware
├── error/               # Error types and handling
├── response/            # HTTP response utilities
├── routes/              # Route definitions
└── state/               # Application state management
```

### Development Guidelines
- **Error Handling:** Use `Result<T, ApiError>` for all fallible operations
- **Logging:** Use appropriate log levels (error, warn, info, debug, trace)
- **Security:** Never log sensitive information (passwords, tokens, secrets)
- **Testing:** Write tests for all public functions and critical paths
- **Documentation:** Document all public APIs and complex logic

### Adding New Features
1. Define data models in `entity/`
2. Create DTOs in `dto/`
3. Implement business logic in `service/`
4. Add data access in `repository/`
5. Create HTTP handlers in `handler/`
6. Define routes in `routes/`
7. Add tests for new functionality

### Code Standards
- Follow Rust naming conventions
- Use `rustfmt` for code formatting
- Run `cargo clippy` for linting
- Write comprehensive tests
- Update documentation for new features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [SQLx](https://github.com/launchbadge/sqlx) - Database toolkit
- [Casbin](https://github.com/casbin/casbin) - Authorization library
- [Casbin-RS](https://github.com/casbin/casbin-rs) - Rust implementation
- [Axum-Casbin](https://github.com/casbin-rs/axum-casbin) - Axum integration
- [Sqlx-Adapter](https://github.com/casbin-rs/sqlx-adapter) - Database adapter
- [jsonwebtoken](https://github.com/Keats/jsonwebtoken) - JWT implementation
- [bcrypt](https://github.com/Keats/rust-bcrypt) - Password hashing
- [tracing](https://github.com/tokio-rs/tracing) - Logging framework

## Support

For questions, issues, or contributions:
- Create an issue on GitHub
- Check the documentation in `docs/` directory
- Review the test scenarios in `tests\http\test.http`

---

**Note:** This framework implements advanced security features including JWT authentication with device fingerprinting and enterprise-grade RBAC authorization with Casbin. Always review and test security implementations before deploying to production.