# NovaMart Backend - Dual Authentication Setup Guide

## Overview

This Spring Boot backend now supports **dual authentication** with both:
1. **Local JWT Authentication** (HS256) - for traditional username/password login
2. **Asgardeo OAuth2 Authentication** (RS256) - for SSO login via WSO2 Asgardeo

## Issues Fixed

### 1. Configuration Problems
- ❌ **Before**: Placeholder `YOUR_ORG_NAME` in application.properties
- ✅ **After**: Environment variable-based configuration with proper validation

### 2. Token Detection Issues
- ❌ **Before**: Basic algorithm detection with poor error handling
- ✅ **After**: Enhanced token type detection with comprehensive logging

### 3. Authority Extraction Problems
- ❌ **Before**: Limited role claim support
- ✅ **After**: Multiple claim sources (groups, roles, scopes, authorities)

### 4. JWKS URI Configuration
- ❌ **Before**: Incorrect URI format and missing validation
- ✅ **After**: Proper JWKS endpoint with lazy initialization

## Setup Instructions

### 1. Environment Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Required Asgardeo Configuration
ASGARDEO_ORG_NAME=your-actual-org-name
ASGARDEO_CLIENT_ID=your-client-id
ASGARDEO_CLIENT_SECRET=your-client-secret

# Database
MONGODB_URI=your-mongodb-connection-string

# JWT Secret (for local auth)
JWT_SECRET=your-secure-jwt-secret-minimum-32-characters
```

### 2. Asgardeo Application Setup

1. **Create Application** in Asgardeo Console:
   - Application Type: `Single Page Application` or `Traditional Web Application`
   - Grant Types: `Authorization Code`, `Refresh Token`
   - Allowed Origins: Your frontend URL

2. **Configure Scopes**:
   - `openid` (required)
   - `profile` (for user info)
   - `email` (for email claim)
   - `groups` (for role-based access)

3. **Role Mapping**:
   - Create roles in Asgardeo (e.g., `admin`, `user`, `manager`)
   - Assign users to appropriate roles
   - Roles will be mapped to Spring Security authorities with `ROLE_` prefix

### 3. Frontend Token Usage

#### For Local JWT (existing):
```javascript
// Login response contains JWT
const response = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});
const { token } = await response.json();

// Use in API calls
fetch('/api/orders', {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

#### For Asgardeo OAuth2:
```javascript
// After Asgardeo login, use the access_token (not id_token)
const accessToken = asgardeoResponse.access_token;

// Use in API calls
fetch('/api/orders', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});
```

## Authentication Flow

### Local JWT Flow (HS256)
1. User submits credentials to `/api/auth/login`
2. Backend validates credentials
3. Backend generates HS256 JWT with user roles
4. Frontend receives JWT and uses for API calls
5. `DualAuthenticationFilter` detects HS256 algorithm
6. Token validated using local JWT secret
7. User authenticated with extracted roles

### Asgardeo OAuth2 Flow (RS256)
1. Frontend redirects to Asgardeo for authentication
2. User authenticates with Asgardeo
3. Asgardeo returns access_token (RS256 JWT)
4. Frontend uses access_token for API calls
5. `DualAuthenticationFilter` detects RS256 algorithm
6. Token validated using Asgardeo JWKS endpoint
7. User authenticated with roles from JWT claims

## Token Claims Mapping

### Local JWT Claims:
```json
{
  "sub": "username",
  "email": "user@example.com",
  "roles": ["USER", "ADMIN"],
  "groups": ["USER", "ADMIN"],
  "type": "LOCAL_JWT",
  "iat": 1234567890,
  "exp": 1234567890
}
```

### Asgardeo JWT Claims:
```json
{
  "sub": "user-uuid",
  "preferred_username": "john.doe",
  "email": "john.doe@company.com",
  "groups": ["admin", "users"],
  "scope": "openid profile email groups",
  "iss": "https://api.asgardeo.io/t/your-org/oauth2/token",
  "aud": "your-client-id"
}
```

## Authority Extraction

The filter extracts authorities from multiple claim sources:

1. **groups** - Primary role source for Asgardeo
2. **roles** - Alternative role source
3. **application_roles** - App-specific roles
4. **scope** - OAuth2 scopes (prefixed with `SCOPE_`)
5. **authorities** - Direct authority claims

All roles are converted to Spring Security authorities with `ROLE_` prefix.

## Debugging

Enable debug logging in `application.properties`:
```properties
logging.level.com.ecommerce.security=DEBUG
logging.level.org.springframework.security=DEBUG
```

### Common Issues & Solutions

1. **403 Forbidden with Asgardeo Token**:
   - Check `ASGARDEO_ORG_NAME` is set correctly
   - Verify JWKS URI is accessible: `https://api.asgardeo.io/t/{org}/oauth2/jwks`
   - Ensure using `access_token` not `id_token`

2. **No Roles Found**:
   - Check Asgardeo application has `groups` scope
   - Verify user is assigned to roles in Asgardeo
   - Check JWT claims in logs

3. **Token Type Detection Failed**:
   - Verify JWT format (3 parts separated by dots)
   - Check algorithm in JWT header
   - Review debug logs for token parsing errors

## Security Considerations

1. **JWT Secrets**: Use strong, unique secrets for local JWT signing
2. **HTTPS**: Always use HTTPS in production
3. **Token Expiration**: Configure appropriate token lifetimes
4. **CORS**: Restrict allowed origins to your frontend domains
5. **Rate Limiting**: Configure rate limits to prevent abuse

## Testing

### Test Local Authentication:
```bash
# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'

# Use returned token
curl -X GET http://localhost:8080/api/orders \
  -H "Authorization: Bearer YOUR_LOCAL_JWT_TOKEN"
```

### Test Asgardeo Authentication:
```bash
# Use Asgardeo access token
curl -X GET http://localhost:8080/api/orders \
  -H "Authorization: Bearer YOUR_ASGARDEO_ACCESS_TOKEN"
```

## Architecture

```
Frontend (Next.js)
    ↓
    ├── Local Login → Local JWT (HS256)
    └── Asgardeo Login → Access Token (RS256)
    ↓
Spring Security Filter Chain
    ↓
DualAuthenticationFilter
    ├── Detects token type (HS256 vs RS256)
    ├── Local JWT → JwtTokenService validation
    └── Asgardeo JWT → JWKS validation
    ↓
SecurityContext with Authentication
    ↓
Protected API Endpoints
```

This setup allows seamless coexistence of both authentication methods without breaking existing functionality.
