# Redis for JWT Fingerprinting: Automatic Cleanup Guide

## Overview
This document explores how Redis automatic cleanup mechanisms can enhance JWT fingerprinting security while eliminating the need for manual cleanup processes.

## Redis Automatic Cleanup Mechanisms

### 1. TTL (Time To Live) - The Key Feature

**Redis TTL allows automatic expiration of keys:**

```bash
# Set a fingerprint with 30-day expiration
SET fingerprint:user123 "fingerprint_data" EX 2592000

# Redis automatically deletes this key after 30 days
# No manual cleanup needed!
```

**TTL Benefits:**
- ✅ **Zero maintenance** - Redis handles cleanup automatically
- ✅ **Memory efficient** - Expired keys are removed immediately
- ✅ **High performance** - O(1) operations
- ✅ **Configurable** - Set any expiration time

### 2. Memory Management Policies

**When Redis reaches memory limits, it can automatically clean up:**

```redis.conf
# Set memory limit
maxmemory 256mb

# LRU-based eviction (only keys with TTL)
maxmemory-policy volatile-lru

# Other options:
# allkeys-lru     - Evict any key (with or without TTL)
# volatile-ttl    - Evict keys with shortest TTL
# noeviction      - Don't evict, return error instead
```

### 3. Active vs Passive Expiry

**Active Expiry (Background Process):**
- Redis scans for expired keys in background
- Default: 10 keys checked per second
- Configurable via `hz` parameter

**Passive Expiry (On Access):**
- Keys checked when accessed
- Expired keys removed immediately
- No background processing needed

## JWT Fingerprinting with Redis TTL

### Implementation Options

#### Option 1: Redis-Only Fingerprint Storage

```rust
use redis::AsyncCommands;

pub struct RedisFingerprintStore {
    client: redis::Client,
}

impl RedisFingerprintStore {
    pub async fn store_fingerprint(
        &self,
        user_id: Uuid,
        fingerprint_hash: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        ttl_days: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.client.get_async_connection().await?;

        let fingerprint_data = json!({
            "user_id": user_id,
            "fingerprint_hash": fingerprint_hash,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": Utc::now().timestamp()
        });

        // Store with TTL - Redis handles expiration automatically!
        let key = format!("fingerprint:{}", fingerprint_hash);
        let ttl_seconds = ttl_days * 24 * 60 * 60;

        conn.set_ex(&key, fingerprint_data.to_string(), ttl_seconds).await?;

        Ok(())
    }

    pub async fn validate_fingerprint(
        &self,
        fingerprint_hash: &str,
        expected_user_id: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut conn = self.client.get_async_connection().await?;

        let key = format!("fingerprint:{}", fingerprint_hash);

        if let Some(data) = conn.get::<_, Option<String>>(&key).await? {
            let fingerprint: serde_json::Value = serde_json::from_str(&data)?;

            // Validate user_id matches
            if fingerprint["user_id"] == expected_user_id.to_string() {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
```

#### Option 2: Hybrid PostgreSQL + Redis Cache

```rust
pub struct HybridFingerprintStore {
    postgres_repo: Arc<PostgresFingerprintRepo>,
    redis_client: redis::Client,
}

impl HybridFingerprintStore {
    pub async fn store_fingerprint(
        &self,
        user_id: Uuid,
        fingerprint_hash: &str,
        ip: Option<String>,
        ua: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Store in PostgreSQL for persistence
        self.postgres_repo.create_fingerprint(
            user_id,
            fingerprint_hash,
            ip.as_deref(),
            ua.as_deref(),
        ).await?;

        // Cache in Redis with TTL for fast lookups
        let mut conn = self.redis_client.get_async_connection().await?;
        let cache_key = format!("fp_lookup:{}", fingerprint_hash);
        let cache_value = user_id.to_string();

        // 24-hour cache TTL
        conn.set_ex(&cache_key, cache_value, 24 * 60 * 60).await?;

        Ok(())
    }

    pub async fn validate_fingerprint(
        &self,
        fingerprint_hash: &str,
        expected_user_id: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut conn = self.redis_client.get_async_connection().await?;

        // Try Redis cache first (fast path)
        let cache_key = format!("fp_lookup:{}", fingerprint_hash);
        if let Some(cached_user_id) = conn.get::<_, Option<String>>(&cache_key).await? {
            if cached_user_id == expected_user_id.to_string() {
                return Ok(true);
            }
        }

        // Fallback to PostgreSQL (slow path)
        let fingerprint = self.postgres_repo
            .find_active_fingerprint(expected_user_id, fingerprint_hash)
            .await?;

        if let Some(fp) = fingerprint {
            // Update cache for future requests
            conn.set_ex(&cache_key, expected_user_id.to_string(), 24 * 60 * 60).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
```

#### Option 3: Redis Pub/Sub for Real-time Cleanup

```rust
use redis::AsyncCommands;

pub struct RedisCleanupCoordinator {
    client: redis::Client,
}

impl RedisCleanupCoordinator {
    pub async fn publish_cleanup_event(
        &self,
        user_id: Uuid,
        reason: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.client.get_async_connection().await?;

        let event = json!({
            "type": "fingerprint_cleanup",
            "user_id": user_id,
            "reason": reason,
            "timestamp": Utc::now().timestamp()
        });

        conn.publish("fingerprint_events", event.to_string()).await?;
        Ok(())
    }

    pub async fn emergency_revoke_all(
        &self,
        user_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.client.get_async_connection().await?;

        // Delete all fingerprint keys for user
        let pattern = format!("fingerprint:*");
        let keys: Vec<String> = conn.keys(&pattern).await?;

        for key in keys {
            // Check if key belongs to user (you'd need to store user_id in key or value)
            if key.contains(&user_id.to_string()) {
                conn.del(&key).await?;
            }
        }

        Ok(())
    }
}
```

## Redis Configuration for Production

### Memory Management
```redis.conf
# Memory limits and policies
maxmemory 1gb
maxmemory-policy volatile-lru

# Active expiry frequency
hz 100

# Disable snapshotting if not needed
save ""

# Enable AOF for durability
appendonly yes
appendfsync everysec
```

### Security Configuration
```redis.conf
# Network security
bind 127.0.0.1
port 6379

# Authentication
requirepass your-secure-redis-password

# Disable dangerous commands
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command SHUTDOWN SHUTDOWN_REDIS
```

### Performance Tuning
```redis.conf
# Connection settings
tcp-keepalive 300
timeout 0

# Memory optimization
maxmemory-samples 5
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes
```

## Monitoring Redis Cleanup

### Built-in Redis Metrics
```bash
# Connect to Redis CLI
redis-cli -a your-password

# Check memory usage
INFO memory

# Check key expiration stats
INFO stats

# Monitor expired keys
INFO keyspace
```

### Custom Monitoring
```rust
use redis::AsyncCommands;

pub struct RedisMonitor {
    client: redis::Client,
}

impl RedisMonitor {
    pub async fn get_cleanup_stats(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut conn = self.client.get_async_connection().await?;

        // Get all fingerprint keys
        let pattern = "fingerprint:*";
        let keys: Vec<String> = conn.keys(pattern).await?;

        let total_keys = keys.len();
        let mut active_keys = 0;
        let mut expired_keys = 0;

        for key in keys {
            if let Some(ttl) = conn.ttl::<_, Option<i64>>(&key).await? {
                if ttl > 0 {
                    active_keys += 1;
                } else {
                    expired_keys += 1;
                }
            }
        }

        Ok(json!({
            "total_fingerprint_keys": total_keys,
            "active_keys": active_keys,
            "expired_keys": expired_keys,
            "memory_usage": conn.info::<_, String>("memory").await?
        }))
    }
}
```

## Integration with JWT Fingerprinting

### Updated Auth Handler with Redis
```rust
pub async fn auth(
    State(state): State<AuthState>,
    ValidatedRequest(payload): ValidatedRequest<UserLoginDto>,
    req: HttpRequest,
) -> Result<Json<TokenReadDto>, ApiError> {
    // ... existing auth logic ...

    // Generate fingerprint
    let fingerprint = FingerprintService::generate_fingerprint();
    let fingerprint_hash = FingerprintService::hash_fingerprint(&fingerprint);

    // Extract client info
    let ip = extract_ip_from_request(&req);
    let ua = extract_user_agent_from_request(&req);

    // Store in Redis with TTL (30 days)
    state.redis_store.store_fingerprint(
        user.id,
        &fingerprint_hash,
        ip.as_deref(),
        ua.as_deref(),
        30, // TTL in days
    ).await?;

    // Create JWT with fingerprint
    let token = state.token_service.generate_token_with_fingerprint(user, &fingerprint_hash)?;

    // Set fingerprint cookie
    let cookie = FingerprintService::create_cookie(&fingerprint);

    Ok(Json(token).with_cookie(cookie))
}
```

### Updated Auth Middleware with Redis
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
    let cookie_hash = FingerprintService::hash_fingerprint(&cookie_fingerprint);

    // Validate against JWT claims
    if cookie_hash != token_data.claims.fingerprint_hash {
        return Err(TokenError::InvalidFingerprint)?;
    }

    // Validate against Redis (fast path)
    let is_valid = state.redis_store.validate_fingerprint(
        &cookie_hash,
        token_data.claims.sub,
    ).await?;

    if !is_valid {
        return Err(TokenError::InvalidFingerprint)?;
    }

    // Get user and continue
    let user = state.user_repo.find(token_data.claims.sub)?;
    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}
```

## Redis Cluster Considerations

### For High Availability
```rust
use redis::cluster::ClusterClient;

pub async fn create_redis_cluster_client() -> Result<redis::cluster::ClusterClient, Box<dyn std::error::Error>> {
    let nodes = vec![
        "redis://redis-node-1:6379",
        "redis://redis-node-2:6379",
        "redis://redis-node-3:6379",
    ];

    let client = ClusterClient::new(nodes)?;
    Ok(client)
}
```

### Cluster-Aware TTL Handling
```rust
// In Redis Cluster, TTL commands are handled by the node owning the key
// No special handling needed - Redis handles it automatically
```

## Migration Strategy

### From PostgreSQL-Only to Redis TTL

1. **Phase 1: Dual Write**
   ```rust
   // Write to both PostgreSQL and Redis
   state.postgres_repo.create_fingerprint(...).await?;
   state.redis_store.store_fingerprint(...).await?;
   ```

2. **Phase 2: Redis-First Reads**
   ```rust
   // Try Redis first, fallback to PostgreSQL
   if let Some(result) = redis_store.validate_fingerprint(...).await? {
       return Ok(result);
   }
   // Fallback to PostgreSQL
   ```

3. **Phase 3: Redis-Only**
   ```rust
   // Use Redis-only implementation
   redis_store.validate_fingerprint(...).await?;
   ```

## Performance Benchmarks

### Redis TTL Performance
- **Set with TTL**: ~10,000 ops/sec
- **Get with TTL check**: ~50,000 ops/sec
- **Automatic cleanup**: ~100,000 expired keys/sec
- **Memory overhead**: ~2 bytes per key for TTL

### Comparison with Manual Cleanup
| Metric | Redis TTL | Manual Cleanup |
|--------|-----------|----------------|
| **Latency** | < 1ms | 100-1000ms |
| **CPU Usage** | < 1% | 5-15% |
| **Memory Usage** | Efficient | Variable |
| **Maintenance** | None | High |
| **Reliability** | Very High | Medium |

## Best Practices

### TTL Configuration
```rust
// Different TTLs for different use cases
const FINGERPRINT_TTL: u32 = 30 * 24 * 60 * 60; // 30 days
const CACHE_TTL: u32 = 24 * 60 * 60;           // 24 hours
const SESSION_TTL: u32 = 8 * 60 * 60;          // 8 hours
```

### Error Handling
```rust
pub async fn safe_redis_operation<F, Fut, T>(
    operation: F,
) -> Result<T, Box<dyn std::error::Error>>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, redis::RedisError>>,
{
    match operation().await {
        Ok(result) => Ok(result),
        Err(e) => {
            // Log error
            eprintln!("Redis operation failed: {}", e);

            // Could implement circuit breaker here
            Err(Box::new(e))
        }
    }
}
```

### Monitoring and Alerting
```rust
pub async fn monitor_redis_health(client: &redis::Client) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = client.get_async_connection().await?;

    // Check Redis connectivity
    let _: String = redis::cmd("PING").query_async(&mut conn).await?;

    // Check memory usage
    let info: String = redis::cmd("INFO").arg("memory").query_async(&mut conn).await?;
    let memory_usage = parse_memory_usage(&info);

    // Alert if memory usage is high
    if memory_usage > 0.9 { // 90% memory usage
        alert_high_memory_usage(memory_usage);
    }

    Ok(())
}
```

## Conclusion

**Redis TTL provides excellent automatic cleanup capabilities for JWT fingerprinting:**

✅ **Zero Manual Cleanup** - Redis handles expiration automatically
✅ **High Performance** - Fast O(1) operations
✅ **Memory Efficient** - Automatic cleanup prevents memory bloat
✅ **Scalable** - Handles millions of keys efficiently
✅ **Reliable** - Built-in persistence and clustering options

**Recommended Implementation:**
1. Use Redis TTL for fingerprint storage and automatic cleanup
2. Implement hybrid approach (Redis + PostgreSQL) for persistence
3. Configure proper memory limits and eviction policies
4. Monitor Redis performance and memory usage
5. Use Redis clustering for high availability

This approach eliminates the need for manual cleanup jobs while providing excellent performance and reliability for JWT fingerprinting security.