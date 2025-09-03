# Project Brief: Next.js Frontend with Rust Backend Integration

## Overview
This project focuses on establishing a robust integration between a Next.js frontend and a Rust-based backend. The primary goal is to demonstrate and implement the necessary architectural components and communication patterns for a modern web application using this technology stack.

## Technical Stack
*   **Frontend**: Next.js
*   **Backend**: Rust with Axum (web framework), async-graphql (GraphQL server), and JWT (JSON Web Token) for authentication.
*   **Database**: PostgreSQL

## Goals
*   Achieve seamless communication between the Next.js frontend and the Rust backend.
*   Implement secure and efficient data exchange via GraphQL.
*   Establish a robust authentication and authorization system using JWT.
*   Provide a scalable and performant backend solution.

## Current Implementation Status
*   Backend infrastructure established with Axum web framework
*   PostgreSQL database connection configured and tested
*   JWT authentication middleware implemented with cookie and bearer token support
*   User model defined with role-based access (initially supporting 'admin' role)
*   Basic health check endpoint (`/api/healthchecker`) operational
*   Environment configuration management via `.env` file
*   Database migration system in place for schema management
*   Rate limiting implemented with sliding window algorithm (5 requests/minute per IP)
*   Structured HTTP response system with standardized error handling

## Architecture Overview
*   **Web Framework**: Axum for async HTTP handling
*   **Database**: PostgreSQL with sqlx for type-safe queries
*   **Authentication**: JWT access tokens (60 min) + refresh tokens (7 days) with rotation
*   **State Management**: Shared application state with database pool and config
*   **Error Handling**: Structured error responses with status codes
*   **Security**: Password hashing with bcrypt, secure token validation
*   **Rate Limiting**: In-memory sliding window algorithm per IP address
*   **Response System**: Standardized HTTP responses with consistent JSON structure

## Database Schema
*   **Users Table**:
    *   `id` (UUID, Primary Key)
    *   `name` (VARCHAR(100), NOT NULL)
    *   `username` (VARCHAR(100), NOT NULL, UNIQUE)
    *   `password` (VARCHAR(100), NOT NULL, hashed)
    *   `role` (VARCHAR(50), NOT NULL, default 'user')
    *   `created_at` (TIMESTAMPTZ, NOT NULL, default NOW())
    *   `updated_at` (TIMESTAMPTZ, NOT NULL, default NOW())
*   **Index**: `users_username_idx` on username for efficient lookups

## Rate Limiting
*   **Algorithm**: Sliding window rate limiting
*   **Limits**: 5 requests per minute per IP address
*   **Storage**: In-memory HashMap with automatic cleanup
*   **Implementation**: Thread-safe using Arc<Mutex>
*   **Response**: HTTP 429 (Too Many Requests) with retry information
*   **Scope**: Applied to authentication endpoints (register/login)

## JWT Security Enhancements
*   **Fingerprinting**: SHA256 hash of random session fingerprint stored in JWT
*   **Cookie Security**: HttpOnly fingerprint cookie prevents XSS attacks
*   **Session Binding**: JWT bound to specific client session via fingerprint validation
*   **Token Theft Protection**: Stolen tokens invalidated if fingerprint doesn't match
*   **OWASP Compliance**: Follows OWASP JWT Cheat Sheet guidelines for token sidejacking prevention

## Refresh Token System
*   **Access Tokens**: Short-lived (60 minutes) for API access
*   **Refresh Tokens**: Long-lived (7 days) for seamless re-authentication
*   **Token Rotation**: New refresh token issued on each refresh for enhanced security
*   **Database Storage**: Refresh tokens hashed and stored securely in database
*   **Automatic Cleanup**: Refresh tokens cleared from database on logout
*   **Family-based Rotation**: Each refresh creates tokens from same family for tracking

## Key Components
*   `src/main.rs`: Application entry point, server initialization, database connection
*   `src/config.rs`: Environment variable parsing and configuration struct
*   `src/models/`: Data models (User, TokenClaims, request/response schemas)
*   `src/auth/jwt.rs`: JWT token creation, fingerprinting, and validation utilities
*   `src/responses/`: Structured HTTP response system with standardized error handling
*   `src/handlers/`: Request handlers with authentication, rate limiting, and logout functionality
*   `src/handlers/general.rs`: Protected route handlers demonstrating JWT authentication
*   `src/utils.rs`: Utility functions for response conversion and common operations
*   `src/middleware/rate_limit.rs`: Rate limiting utilities (currently unused, implemented in handlers)
*   `src/constants.rs`: Application constants including rate limiting configuration
*   `migrations/`: Database schema migrations using sqlx
*   `docs/`: Frontend integration documentation, API guides, and JWT security best practices

## Response Standardization
*   **Consistent API Responses**: All handlers now use standardized response functions
*   **Error Response Format**: Unified JSON error structure with status and message fields
*   **Success Response Format**: Consistent success responses with data field
*   **Type Safety**: Proper error type conversion between different response formats
*   **Handler Consistency**: All handlers follow the same response pattern for maintainability

## API Endpoints
*   `POST /api/auth/register` - User registration with rate limiting
*   `POST /api/auth/login` - User login with JWT + refresh token + fingerprint cookies
*   `POST /api/auth/logout` - Secure logout clearing all cookies and database tokens
*   `POST /api/auth/refresh` - Token refresh with rotation for seamless authentication
*   `GET /api/protected` - Protected route requiring authentication
*   `GET /api/profile` - User profile endpoint with authenticated user data
*   `GET /` - Root protected route demonstrating authentication

## Authentication Flow
1. User credentials submitted via login endpoint
2. Password verified against hashed value in database
3. JWT token generated with user ID as subject
4. Token returned in HTTP-only cookie and/or Authorization header
5. Subsequent requests validated via auth middleware
6. User data retrieved from database and attached to request extensions
7. Protected routes accessible based on authentication status

## Rate Limiting Flow
1. Client IP extracted from request connection info
2. Rate limit store checked for existing client record
3. Request count incremented if within window limits
4. Automatic cleanup of expired entries
5. HTTP 429 response returned when limit exceeded
6. Response includes remaining time until reset
7. Window automatically resets after configured duration