package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/ribeirohugo/go_middlewares/pkg/authentication"
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
	auth := authentication.Auth{
		SigningMethod: jwt.SigningMethodHS256,
		ClaimsKey:     "secret",
	}

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
				jwtSecret,                                // Token secret
				3600,                                     // Token max age
				tt.skipList,                              // Skip list
				map[string][]string{"/admin": {"admin"}}, // Permissions map
				auth,                                     // authentication struct
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
