use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate limit state shared across requests
#[derive(Clone)]
pub struct RateLimitState {
    /// Map of IP address to request history
    attempts: Arc<DashMap<String, Vec<Instant>>>,
    /// Maximum requests per window
    max_requests: u32,
    /// Time window duration
    window_duration: Duration,
}

impl RateLimitState {
    pub fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
            max_requests,
            window_duration: Duration::from_secs(window_seconds),
        }
    }

    /// Check if the IP address is within rate limits
    pub fn check_rate_limit(&self, ip: &str) -> bool {
        let now = Instant::now();
        let window_start = now - self.window_duration;

        // Get or create entry for this IP
        let mut attempts = self.attempts.entry(ip.to_string()).or_insert_with(Vec::new);

        // Remove old attempts outside the window
        attempts.retain(|&time| time > window_start);

        // Check if under limit
        if attempts.len() < self.max_requests as usize {
            attempts.push(now);
            true
        } else {
            false
        }
    }

    /// Clean up old entries to prevent memory leaks
    pub fn cleanup(&self) {
        let now = Instant::now();
        let cutoff = now - self.window_duration * 2; // Keep entries for 2 windows

        self.attempts.retain(|_, attempts| {
            attempts.retain(|&time| time > cutoff);
            !attempts.is_empty()
        });
    }
}

/// Rate limiting middleware for authentication endpoints
pub async fn rate_limit_auth<B>(
    State(state): State<RateLimitState>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    // Extract client IP address
    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .or_else(|| req.headers().get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    // Skip rate limiting for unknown IPs (could be internal requests)
    if client_ip == "unknown" {
        return Ok(next.run(req).await);
    }

    // Check rate limit
    if !state.check_rate_limit(client_ip) {
        // Log rate limit violations - IP addresses are considered PII but necessary for security monitoring
        // In production, consider aggregating or hashing IPs for privacy compliance
        if cfg!(debug_assertions) {
            tracing::warn!("SECURITY: Rate limit exceeded for IP: {}", client_ip);
        } else {
            tracing::warn!("SECURITY: Rate limit exceeded for client from {}", client_ip);
        }

        // Return rate limit exceeded response
        let response = (
            StatusCode::TOO_MANY_REQUESTS,
            [("content-type", "application/json")],
            r#"{"error":"Too many requests","message":"Rate limit exceeded. Please try again later."}"#,
        );
        return Ok(response.into_response());
    }

    // Clean up old entries periodically (every 100 requests roughly)
    if state.attempts.len() % 100 == 0 {
        state.cleanup();
    }

    Ok(next.run(req).await)
}

/// Rate limiting middleware for general endpoints (less restrictive)
pub async fn rate_limit_general<B>(
    State(state): State<RateLimitState>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .or_else(|| req.headers().get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    if client_ip == "unknown" {
        return Ok(next.run(req).await);
    }

    if !state.check_rate_limit(client_ip) {
        tracing::warn!("Rate limit exceeded for IP: {} on general endpoint", client_ip);
        return Ok(StatusCode::TOO_MANY_REQUESTS.into_response());
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_rate_limit_within_bounds() {
        let state = RateLimitState::new(3, 60); // 3 requests per minute
        let ip = "192.168.1.1";

        // Should allow first 3 requests
        assert!(state.check_rate_limit(ip));
        assert!(state.check_rate_limit(ip));
        assert!(state.check_rate_limit(ip));
    }

    #[tokio::test]
    async fn test_rate_limit_exceeded() {
        let state = RateLimitState::new(2, 60); // 2 requests per minute
        let ip = "192.168.1.1";

        // Should allow first 2 requests
        assert!(state.check_rate_limit(ip));
        assert!(state.check_rate_limit(ip));

        // Third request should be blocked
        assert!(!state.check_rate_limit(ip));
    }

    #[tokio::test]
    async fn test_rate_limit_window_reset() {
        let state = RateLimitState::new(2, 1); // 2 requests per second
        let ip = "192.168.1.1";

        // Use up the limit
        assert!(state.check_rate_limit(ip));
        assert!(state.check_rate_limit(ip));
        assert!(!state.check_rate_limit(ip));

        // Wait for window to reset
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should allow requests again
        assert!(state.check_rate_limit(ip));
    }

    #[tokio::test]
    async fn test_cleanup_old_entries() {
        let state = RateLimitState::new(1, 1);
        let ip1 = "192.168.1.1";
        let ip2 = "192.168.1.2";

        // Add entries for both IPs
        assert!(state.check_rate_limit(ip1));
        assert!(state.check_rate_limit(ip2));

        // Manually set old timestamp for ip1
        if let Some(mut attempts) = state.attempts.get_mut(ip1) {
            attempts[0] = Instant::now() - Duration::from_secs(10);
        }

        // Cleanup should remove old entries
        state.cleanup();

        // ip1 should be cleaned up, ip2 should remain
        assert!(!state.attempts.contains_key(ip1));
        assert!(state.attempts.contains_key(ip2));
    }
}