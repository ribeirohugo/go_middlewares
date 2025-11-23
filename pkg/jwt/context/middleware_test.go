package context

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	jwtAuth "github.com/ribeirohugo/go_middlewares/pkg/jwt"
)

// Mock handler to test middleware behavior
func mockHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"success"}`)) // Ensure a response body
	})
}

func generateToken(secret, role string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"role": role,
	})
	return token.SignedString([]byte(secret))
}

func TestJWT_Middleware(t *testing.T) {
	jwtSecret := "secret"

	tests := []struct {
		name           string
		token          string
		skipList       []string
		role           string
		requestPath    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid token",
			role:           "admin",
			requestPath:    "/admin",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
		{
			name:           "Invalid token",
			role:           "admin",
			token:          "invalid-token",
			requestPath:    "/admin",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"message":"unauthorized"}`,
		},
		{
			name:           "Missing token",
			requestPath:    "/admin",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"message":"unauthorized"}`,
		},
		{
			name:           "Skip list (no token required)",
			skipList:       []string{"/admin"},
			requestPath:    "/admin",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
		{
			name:           "Unauthorized role",
			role:           "guest",
			requestPath:    "/admin",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"message":"unauthorized"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate token if a role is provided
			var tokenString string
			if tt.role != "" {
				var err error
				tokenString, err = generateToken(jwtSecret, tt.role)
				if err != nil {
					t.Fatalf("could not generate token: %v", err)
				}
			}

			// Create JWT middleware
			jwtMiddleware := New(
				"admin",                                  // Admin role
				tt.skipList,                              // Skip list
				map[string][]string{"/admin": {"admin"}}, // Permissions map
				jwtAuth.Default(
					jwtSecret, // Token secret
					3600,      // Token max age
				),
			)

			// Create request
			req, err := http.NewRequest(http.MethodGet, tt.requestPath, nil)
			if err != nil {
				t.Fatalf("could not create request: %v", err)
			}

			// Set Authorization header if token exists
			if tt.token != "" {
				req.Header.Add("Authorization", "Bearer "+tt.token)
			} else if tokenString != "" {
				req.Header.Add("Authorization", "Bearer "+tokenString)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call middleware
			jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)

			// Assert status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Assert response body only if expected
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, rr.Body.String())
			}
		})
	}
}

func TestJWT_Middleware_Blacklist(t *testing.T) {
	t.Run("should reject blacklisted token after logout", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: 3600,
		}
		jwtMiddleware := New("admin", []string{}, map[string][]string{}, auth)

		// Create a token
		tokenString, err := jwtMiddleware.Login(nil, "user123", "service", "app", "admin")
		assert.NoError(t, err)

		// Verify token works before logout
		req1 := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req1.Header.Add("Authorization", "Bearer "+tokenString)
		rr1 := httptest.NewRecorder()
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr1, req1)
		assert.Equal(t, http.StatusOK, rr1.Code, "Token should work before logout")

		// Parse token to get claims for logout
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})
		claims := token.Claims.(jwt.MapClaims)
		ctx := context.WithValue(context.Background(), auth.ClaimsKey, &claims)

		// Logout - this should blacklist the token
		_, err = jwtMiddleware.Logout(ctx)
		assert.NoError(t, err)

		// Try to use the same token after logout
		req2 := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req2.Header.Add("Authorization", "Bearer "+tokenString)
		rr2 := httptest.NewRecorder()
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr2, req2)

		// Token should be rejected
		assert.Equal(t, http.StatusUnauthorized, rr2.Code, "Token should be rejected after logout")
		assert.Contains(t, rr2.Body.String(), "token has been revoked")
	})

	t.Run("should allow new token after logout of old token", func(t *testing.T) {
		// Arrange
		auth := jwtAuth.Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: 3600,
		}
		jwtMiddleware := New("admin", []string{}, map[string][]string{}, auth)

		// Create first token
		token1, err := jwtMiddleware.Login(nil, "user123", "service", "app", "admin")
		assert.NoError(t, err)

		// Parse token to get claims for logout
		parsedToken, _ := jwt.Parse(token1, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})
		claims := parsedToken.Claims.(jwt.MapClaims)
		ctx := context.WithValue(context.Background(), auth.ClaimsKey, &claims)

		// Logout first token
		_, err = jwtMiddleware.Logout(ctx)
		assert.NoError(t, err)

		// Create a new token for the same user
		token2, err := jwtMiddleware.Login(nil, "user123", "service", "app", "admin")
		assert.NoError(t, err)

		// New token should work
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Add("Authorization", "Bearer "+token2)
		rr := httptest.NewRecorder()
		jwtMiddleware.Middleware(mockHandler()).ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "New token should work")
	})
}

