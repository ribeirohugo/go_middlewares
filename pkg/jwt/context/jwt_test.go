package context

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwtAuth "github.com/ribeirohugo/go_middlewares/pkg/jwt"
)

func TestNew(t *testing.T) {
	t.Run("should create JWT middleware with all parameters", func(t *testing.T) {
		// Arrange
		adminRole := "admin"
		skipList := []string{"/public", "/health"}
		permissionsMap := map[string][]string{
			"/api/users": {"admin", "user"},
		}
		auth := jwtAuth.Default("secret", 3600)

		// Act
		jwtMiddleware := New(adminRole, skipList, permissionsMap, auth)

		// Assert
		assert.Equal(t, adminRole, jwtMiddleware.AdminRole)
		assert.Equal(t, skipList, jwtMiddleware.SkipList)
		assert.Equal(t, permissionsMap, jwtMiddleware.PermissionsMap)
	})

	t.Run("should create JWT middleware with empty skip list", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Default("secret", 3600)

		// Act
		jwtMiddleware := New("admin", []string{}, map[string][]string{}, auth)

		// Assert
		assert.Empty(t, jwtMiddleware.SkipList)
	})

	t.Run("should create JWT middleware with empty permissions map", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Default("secret", 3600)

		// Act
		jwtMiddleware := New("admin", []string{"/public"}, map[string][]string{}, auth)

		// Assert
		assert.Empty(t, jwtMiddleware.PermissionsMap)
	})
}

func TestJWT_GetClaims(t *testing.T) {
	t.Run("should extract claims from context", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Auth{
			ClaimsKey:     "test-key",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
		}
		jwtMiddleware := JWT{auth: auth}

		// Create a real token to get properly formatted claims
		tokenString, _ := auth.ClaimsSignedToken("user123", "service", "app", "admin")

		// Parse the token to get valid MapClaims
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})
		mapClaims := token.Claims.(jwt.MapClaims)

		ctx := context.WithValue(context.Background(), auth.ClaimsKey, &mapClaims)

		// Act
		claims, err := jwtMiddleware.GetClaims(ctx)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "user123", claims.Subject)
		assert.Equal(t, "admin", claims.Role)
	})

	t.Run("should return error when no claims in context", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Auth{
			ClaimsKey: "test-key",
		}
		jwtMiddleware := JWT{auth: auth}
		ctx := context.Background()

		// Act
		_, err := jwtMiddleware.GetClaims(ctx)

		// Assert
		require.Error(t, err)
	})
}

func TestJWT_Logout(t *testing.T) {
	t.Run("should clear claims from context", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Auth{
			ClaimsKey: "test-key",
		}
		jwtMiddleware := JWT{auth: auth}

		mapClaims := jwt.MapClaims{"sub": "user123"}
		ctx := context.WithValue(context.Background(), auth.ClaimsKey, &mapClaims)

		// Act
		newCtx, err := jwtMiddleware.Logout(ctx)

		// Assert
		require.NoError(t, err)
		assert.Nil(t, newCtx.Value(auth.ClaimsKey))
	})

	t.Run("should work even if no claims present", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Auth{
			ClaimsKey: "test-key",
		}
		jwtMiddleware := JWT{auth: auth}
		ctx := context.Background()

		// Act
		newCtx, err := jwtMiddleware.Logout(ctx)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, newCtx)
	})
}

func TestJWT_Login(t *testing.T) {
	t.Run("should generate valid token", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
		}
		jwtMiddleware := JWT{auth: auth}
		ctx := context.Background()

		// Act
		token, err := jwtMiddleware.Login(ctx, "user123", "service", "app", "admin")

		// Assert
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})
		require.NoError(t, err)
		assert.True(t, parsedToken.Valid)
	})

	t.Run("should include all claims in token", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
		}
		jwtMiddleware := JWT{auth: auth}

		// Act
		token, err := jwtMiddleware.Login(context.Background(), "user456", "my-service", "my-app", "user")

		// Assert
		require.NoError(t, err)

		parsedToken, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})
		claims := parsedToken.Claims.(jwt.MapClaims)

		assert.Equal(t, "user456", claims["sub"])
		assert.Equal(t, "my-service", claims["iss"])
		assert.Equal(t, "my-app", claims["aud"])
		assert.Equal(t, "user", claims["role"])
	})

	t.Run("should generate different tokens for different users", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
		}
		jwtMiddleware := JWT{auth: auth}

		// Act
		token1, _ := jwtMiddleware.Login(context.Background(), "user1", "service", "app", "user")
		token2, _ := jwtMiddleware.Login(context.Background(), "user2", "service", "app", "user")

		// Assert
		assert.NotEqual(t, token1, token2)
	})
}

func TestJWT_Middleware_SkipList(t *testing.T) {
	t.Run("should skip authentication for endpoints in skip list", func(t *testing.T) {
		// Arrange
		skipList := []string{"/public", "/health", "/api/login"}
		jwtMiddleware := New(
			"admin",
			skipList,
			map[string][]string{},
			jwtAuth.Default("secret", 3600),
		)

		testCases := []string{"/public", "/health", "/api/login", "/public/users", "/health/check"}

		for _, path := range testCases {
			t.Run(path, func(t *testing.T) {
				// Arrange
				req := httptest.NewRequest(http.MethodGet, path, nil)
				rr := httptest.NewRecorder()

				// Act
				jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

				// Assert
				assert.Equal(t, http.StatusOK, rr.Code)
			})
		}
	})

	t.Run("should require authentication for endpoints not in skip list", func(t *testing.T) {
		// Arrange
		skipList := []string{"/public"}
		jwtMiddleware := New(
			"admin",
			skipList,
			map[string][]string{},
			jwtAuth.Default("secret", 3600),
		)

		req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestJWT_Middleware_RolePermissions(t *testing.T) {
	t.Run("should allow admin role to access all endpoints", func(t *testing.T) {
		// Arrange
		secret := "test-secret"
		auth := jwtAuth.Default(secret, 3600)
		jwtMiddleware := New(
			"admin",
			[]string{},
			map[string][]string{
				"/api/users": {"user"},
			},
			auth,
		)

		// Generate admin token
		token, _ := jwtMiddleware.Login(context.Background(), "admin1", "service", "app", "admin")

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("should enforce role permissions for non-admin users", func(t *testing.T) {
		// Arrange
		secret := "test-secret"
		auth := jwtAuth.Default(secret, 3600)
		jwtMiddleware := New(
			"admin",
			[]string{},
			map[string][]string{
				"/api/admin": {"admin"},
			},
			auth,
		)

		// Generate user token (not admin)
		token, _ := jwtMiddleware.Login(context.Background(), "user1", "service", "app", "user")

		req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("should allow access to endpoints with correct role", func(t *testing.T) {
		// Arrange
		secret := "test-secret"
		auth := jwtAuth.Default(secret, 3600)
		jwtMiddleware := New(
			"admin",
			[]string{},
			map[string][]string{
				"/api/reports": {"manager", "admin"},
			},
			auth,
		)

		// Generate manager token
		token, _ := jwtMiddleware.Login(context.Background(), "manager1", "service", "app", "manager")

		req := httptest.NewRequest(http.MethodGet, "/api/reports", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("should allow access to unmapped endpoints for authenticated users", func(t *testing.T) {
		// Arrange
		secret := "test-secret"
		auth := jwtAuth.Default(secret, 3600)
		jwtMiddleware := New(
			"admin",
			[]string{},
			map[string][]string{
				"/api/admin": {"admin"},
			},
			auth,
		)

		// Generate user token
		token, _ := jwtMiddleware.Login(context.Background(), "user1", "service", "app", "user")

		req := httptest.NewRequest(http.MethodGet, "/api/public-data", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestJWT_Middleware_Authorization(t *testing.T) {
	t.Run("should reject requests without Authorization header", func(t *testing.T) {
		// Arrange
		jwtMiddleware := New(
			"admin",
			[]string{},
			map[string][]string{},
			jwtAuth.Default("secret", 3600),
		)

		req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "unauthorized")
	})

	t.Run("should reject requests with malformed token", func(t *testing.T) {
		// Arrange
		jwtMiddleware := New(
			"admin",
			[]string{},
			map[string][]string{},
			jwtAuth.Default("secret", 3600),
		)

		req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("should accept valid Bearer token", func(t *testing.T) {
		// Arrange
		secret := "test-secret"
		auth := jwtAuth.Default(secret, 3600)
		jwtMiddleware := New("admin", []string{}, map[string][]string{}, auth)

		token, _ := jwtMiddleware.Login(context.Background(), "user1", "service", "app", "user")

		req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("should reject token with wrong signing method", func(t *testing.T) {
		// Arrange
		jwtMiddleware := New(
			"admin",
			[]string{},
			map[string][]string{},
			jwtAuth.Default("secret", 3600),
		)

		// Create token with different signing method
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
			"sub":  "user1",
			"role": "user",
		})
		tokenString, _ := token.SignedString([]byte("secret"))

		req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestJWT_Middleware_ClaimsContext(t *testing.T) {
	t.Run("should store claims in request context", func(t *testing.T) {
		// Arrange
		secret := "test-secret"
		auth := jwtAuth.Default(secret, 3600)
		jwtMiddleware := New("admin", []string{}, map[string][]string{}, auth)

		token, _ := jwtMiddleware.Login(context.Background(), "user123", "service", "app", "user")

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			claims, err := jwtMiddleware.GetClaims(r.Context())
			assert.NoError(t, err)
			assert.Equal(t, "user123", claims.Subject)
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		// Act
		jwtMiddleware.Middleware(testHandler).ServeHTTP(rr, req)

		// Assert
		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
