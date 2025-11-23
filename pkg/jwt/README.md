# JWT Middleware

## Overview
This package provides JWT (JSON Web Token) authentication middleware for Go applications. It includes support for token generation, validation, role-based access control (RBAC), and optional Redis-backed token storage for enhanced security.

## Features
- JWT token generation and validation
- Role-based access control (RBAC) with permission mapping
- Support for custom signing methods (default: HS256)
- Optional Redis integration for token management and revocation
- Context-based token storage
- Skip list for public endpoints
- Token expiration handling
- Admin role bypass for permission checks

## Installation

```sh
go get github.com/ribeirohugo/go_middlewares/pkg/jwt
```

## Package Structure

The JWT package is organized into two main implementations:

- **`context`**: JWT middleware with context-based token storage
- **`redis`**: JWT middleware with Redis-backed token storage for distributed applications

## Usage

### Basic Setup

#### 1. Initialize JWT Authentication

```go
import (
	"github.com/golang-jwt/jwt/v5"
	jwtAuth "github.com/ribeirohugo/go_middlewares/pkg/jwt"
)

// Create authentication configuration
auth := jwtAuth.New("your-secret-key", 3600, jwt.SigningMethodHS256)

// Or use default signing method (HS256)
auth := jwtAuth.Default("your-secret-key", 3600)
```

### Context-Based JWT Middleware

Use this implementation for single-instance applications where tokens are stored in request context.

```go
import (
	jwtContext "github.com/ribeirohugo/go_middlewares/pkg/jwt/context"
)

func main() {
	// Define admin role
	adminRole := "admin"

	// Define endpoints that skip JWT validation
	skipList := []string{
		"/public",
		"/health",
		"/login",
	}

	// Define role-based permissions for specific endpoints
	permissionsMap := map[string][]string{
		"/api/users":   {"admin", "user"},
		"/api/reports": {"admin"},
	}

	// Initialize JWT middleware
	jwtMiddleware := jwtContext.New(
		adminRole,
		skipList,
		permissionsMap,
		auth,
	)

	// Apply middleware to your handlers
	mux := http.NewServeMux()
	mux.Handle("/api/protected", jwtMiddleware.Middleware(http.HandlerFunc(protectedHandler)))

	http.ListenAndServe(":8080", mux)
}
```

### Redis-Based JWT Middleware

Use this implementation for distributed applications where tokens need to be shared across multiple instances or require revocation capabilities.

```go
import (
	"github.com/redis/go-redis/v9"
	jwtRedis "github.com/ribeirohugo/go_middlewares/pkg/jwt/redis"
)

func main() {
	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	// Define configuration (same as context-based)
	adminRole := "admin"
	skipList := []string{"/public", "/health", "/login"}
	permissionsMap := map[string][]string{
		"/api/users": {"admin", "user"},
	}

	// Initialize JWT middleware with Redis
	jwtMiddleware := jwtRedis.New(
		adminRole,
		skipList,
		permissionsMap,
		auth,
		redisClient,
	)

	// Apply middleware
	mux := http.NewServeMux()
	mux.Handle("/api/protected", jwtMiddleware.Middleware(http.HandlerFunc(protectedHandler)))

	http.ListenAndServe(":8080", mux)
}
```

## Token Operations

### Login (Generate Token)

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Generate JWT token
	token, err := jwtMiddleware.Login(
		r.Context(),
		"user123",           // subject (user ID)
		"my-service",        // issuer
		"my-app",            // audience
		"user",              // role
	)
	if err != nil {
		http.Error(w, "Login failed", http.StatusInternalServerError)
		return
	}

	// Return token to client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}
```

### Get Claims from Request

```go
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Extract claims from context
	claims, err := jwtMiddleware.GetClaims(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Access claim data
	userID := claims.Subject
	role := claims.Role
	
	w.Write([]byte(fmt.Sprintf("Hello, user %s with role %s", userID, role)))
}
```

### Logout (Revoke Token)

```go
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Remove token from context/Redis
	ctx, err := jwtMiddleware.Logout(r.Context())
	if err != nil {
		http.Error(w, "Logout failed", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Logged out successfully"))
}
```

## Claims Structure

The JWT token contains the following claims:

```go
type Claims struct {
	ID        string `json:"id"`        // Unique token ID (UUID)
	Subject   string `json:"sub"`       // User ID
	Issuer    string `json:"iss"`       // Token issuer
	Audience  string `json:"aud"`       // Intended audience
	ExpiresAt int64  `json:"exp"`       // Expiration time (Unix timestamp)
	IssuedAt  int64  `json:"iat"`       // Issued at (Unix timestamp)
	Role      string `json:"role"`      // User role for RBAC
}
```

## Role-Based Access Control

### Permission Mapping

Define which roles can access specific endpoints:

```go
permissionsMap := map[string][]string{
	"/api/admin":    {"admin"},                    // Only admin
	"/api/users":    {"admin", "user"},            // Admin and user
	"/api/reports":  {"admin", "manager"},         // Admin and manager
}
```

### Admin Role

The admin role bypasses all permission checks and can access any endpoint (except those in the skip list that don't require authentication).

### Behavior

| Scenario                                       | Expected Behavior                           |
|------------------------------------------------|---------------------------------------------|
| Request with valid token and allowed role      | Request proceeds to handler                 |
| Request with valid token but unauthorized role | `401 Unauthorized`                          |
| Request with expired token                     | `401 Unauthorized` with "token has expired" |
| Request without token                          | `401 Unauthorized`                          |
| Request to endpoint in skip list               | Bypasses JWT validation                     |
| Admin role accessing any endpoint              | Always allowed                              |
| Endpoint not in permissions map                | Allowed for all authenticated users         |

## Client Request Example

### Authorization Header

```http
GET /api/protected HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Using cURL

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8080/api/protected
```

## Error Messages

- `"unauthorized"` - Missing, invalid, or insufficient permissions
- `"token has expired"` - Token expiration time has passed
