# JWT Middleware Documentation

## Overview
The JWT middleware provides authentication and authorization mechanisms for HTTP requests by validating JWT tokens. It ensures secure access to protected endpoints based on user roles and permissions.

## Features
- Validates JWT tokens in the `Authorization` header.
- Skips verification for specified endpoints.
- Checks user roles against endpoint-specific permissions.
- Supports an admin role with full access.
- Returns appropriate error responses for unauthorized or expired tokens.

## Usage

### Middleware Constructor
```go
jwtMiddleware := jwt.New(
    "admin",           // Admin role
    "userClaims",      // Claims key
    "supersecret",     // Token secret key
    3600,               // Token duration in seconds
    []string{"/public"}, // Skip list (endpoints that bypass JWT check)
    map[string][]string{
        "/admin": {"admin"},
        "/user":  {"user", "admin"},
    },
)
```
This initializes the middleware with role-based access control.

### Applying Middleware
```go
handler := jwtMiddleware.Middleware(http.HandlerFunc(yourHandler))
http.Handle("/secure", handler)
```
Wrap your HTTP handler with the JWT middleware before serving requests.

## Behavior

| Scenario                        | Expected Behavior                                                |
|---------------------------------|------------------------------------------------------------------|
| Valid token and authorized role | Proceeds with request handling                                   |
| Expired token                   | Responds with `401 Unauthorized` and `token has expired` message |
| No token provided               | Responds with `401 Unauthorized` and `unauthorized` message      |
| Unauthorized role               | Responds with `401 Unauthorized`                                 |
| Skipped endpoint                | Request proceeds without JWT verification                        |

## Example Requests & Responses

### Valid Request
**Request:**
```
Authorization: Bearer valid.jwt.token
```
**Response:**
```
HTTP 200 OK
```

### Expired Token
**Response:**
```
HTTP 401 Unauthorized
{
    "message": "token has expired"
}
```

### Unauthorized Role
**Response:**
```
HTTP 401 Unauthorized
{
    "message": "Unauthorized"
}
```

### Skipped Endpoint
If `/public` is in `SkipList`, a request to `/public/data` will bypass JWT verification.

## Conclusion
This JWT middleware ensures secure authentication and authorization for API endpoints.
Configure roles and permissions as needed to enforce access control effectively.
