# API Documentation

This directory contains comprehensive documentation for the Andalas API backend.

## Documents

### [Frontend Authentication Guide](./frontend-authentication.md)
Complete guide for frontend developers integrating with the authentication system.

### [JWT Security Guide](./jwt.md)
Comprehensive guide on JWT implementation, security considerations, and best practices based on OWASP standards.

**Topics covered:**
- JWT authentication flow with fingerprinting
- Cookie handling and security (HttpOnly, SameSite)
- sessionStorage vs localStorage security comparison
- JavaScript/React implementation examples
- API endpoint documentation with examples
- Security best practices following OWASP guidelines
- Error handling strategies and troubleshooting
- Testing approaches and integration with [`jwt.md`](../jwt.md)

### Key Features Documented

#### 🔐 **Authentication System**
- JWT tokens with configurable expiration
- Fingerprinting for session security
- HttpOnly cookies preventing XSS
- SameSite protection against CSRF
- Rate limiting (5 requests/minute)

#### 🛡️ **Security Features**
- SHA256 fingerprint hashing
- Automatic token validation
- Secure cookie management
- Session binding protection
- Standardized error responses

#### 📡 **API Endpoints**
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User authentication
- `POST /api/auth/logout` - Session termination
- `GET /api/protected` - Protected resource access
- `GET /api/profile` - User profile data
- `GET /` - Basic protected route

#### 🎯 **Frontend Integration**
- Vanilla JavaScript examples
- React/Next.js implementation
- Authentication context patterns
- Protected route components
- Error handling strategies

## Quick Start

1. **Read the Frontend Guide**: Start with [`frontend-authentication.md`](./frontend-authentication.md)
2. **Understand the Flow**: Review the authentication flow diagram
3. **Check API Examples**: Use the provided code examples
4. **Implement Security**: Follow the security best practices
5. **Test Integration**: Use the testing examples provided

## Response Format

All API responses follow a consistent JSON structure:

### Success Response
```json
{
  "status": "success",
  "message": "Operation successful",
  "data": { ... }
}
```

### Error Response
```json
{
  "status": "error",
  "message": "Error description"
}
```

## Support

For questions about the API or authentication system:
- Check the troubleshooting section in the frontend guide
- Review the error handling examples
- Test with the provided examples in `test.http`