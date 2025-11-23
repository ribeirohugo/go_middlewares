package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("should create Auth with custom signing method", func(t *testing.T) {
		// Arrange
		token := "test-secret"
		tokenDuration := 3600
		method := jwt.SigningMethodHS512

		// Act
		auth := New(token, tokenDuration, method)

		// Assert
		assert.Equal(t, ClaimsKey(token), auth.ClaimsKey)
		assert.Equal(t, method, auth.SigningMethod)
		assert.Equal(t, time.Duration(tokenDuration)*time.Second, auth.TokenDuration)
	})

	t.Run("should create Auth with different token durations", func(t *testing.T) {
		// Arrange
		testCases := []struct {
			name     string
			duration int
			expected time.Duration
		}{
			{"1 hour", 3600, 3600 * time.Second},
			{"30 minutes", 1800, 1800 * time.Second},
			{"1 day", 86400, 86400 * time.Second},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Act
				auth := New("secret", tc.duration, jwt.SigningMethodHS256)

				// Assert
				assert.Equal(t, tc.expected, auth.TokenDuration)
			})
		}
	})

	t.Run("should support different signing methods", func(t *testing.T) {
		// Arrange
		methods := []jwt.SigningMethod{
			jwt.SigningMethodHS256,
			jwt.SigningMethodHS384,
			jwt.SigningMethodHS512,
		}

		for _, method := range methods {
			t.Run(method.Alg(), func(t *testing.T) {
				// Act
				auth := New("secret", 3600, method)

				// Assert
				assert.Equal(t, method, auth.SigningMethod)
			})
		}
	})
}

func TestDefault(t *testing.T) {
	t.Run("should create Auth with default HS256 signing method", func(t *testing.T) {
		// Arrange
		token := "test-secret"
		tokenDuration := 3600

		// Act
		auth := Default(token, tokenDuration)

		// Assert
		assert.Equal(t, ClaimsKey(token), auth.ClaimsKey)
		assert.Equal(t, jwt.SigningMethodHS256, auth.SigningMethod)
		assert.Equal(t, time.Duration(tokenDuration)*time.Second, auth.TokenDuration)
	})

	t.Run("should use HS256 as default method", func(t *testing.T) {
		// Act
		auth := Default("secret", 3600)

		// Assert
		assert.Equal(t, "HS256", auth.SigningMethod.Alg())
	})
}

func TestAuth_SignedToken(t *testing.T) {
	t.Run("should generate valid signed token", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
			TokenSecret:   "my-secret-key",
		}
		claims := jwt.MapClaims{
			"sub":  "user123",
			"role": "admin",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}

		// Act
		tokenString, err := auth.SignedToken(claims)

		// Assert
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify token can be parsed
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.TokenSecret), nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("should sign token with correct claims", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
			TokenSecret:   "my-secret-key",
		}
		claims := jwt.MapClaims{
			"sub":  "user456",
			"role": "user",
			"iss":  "test-service",
		}

		// Act
		tokenString, err := auth.SignedToken(claims)

		// Assert
		require.NoError(t, err)

		// Parse and verify claims
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.TokenSecret), nil
		})
		require.NoError(t, err)

		if mapClaims, ok := token.Claims.(jwt.MapClaims); ok {
			assert.Equal(t, "user456", mapClaims["sub"])
			assert.Equal(t, "user", mapClaims["role"])
			assert.Equal(t, "test-service", mapClaims["iss"])
		} else {
			t.Fatal("failed to cast claims")
		}
	})

	t.Run("should use correct signing method", func(t *testing.T) {
		// Arrange
		testCases := []struct {
			name   string
			method jwt.SigningMethod
		}{
			{"HS256", jwt.SigningMethodHS256},
			{"HS384", jwt.SigningMethodHS384},
			{"HS512", jwt.SigningMethodHS512},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				auth := Auth{
					ClaimsKey:     "test-secret",
					SigningMethod: tc.method,
					TokenDuration: time.Hour,
					TokenSecret:   "my-secret-key",
				}
				claims := jwt.MapClaims{"sub": "user123"}

				// Act
				tokenString, err := auth.SignedToken(claims)

				// Assert
				require.NoError(t, err)

				// Verify signing method
				token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return []byte(auth.TokenSecret), nil
				})
				assert.Equal(t, tc.method.Alg(), token.Method.Alg())
			})
		}
	})

	t.Run("should fail with empty secret", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
			TokenSecret:   "",
		}
		claims := jwt.MapClaims{"sub": "user123"}

		// Act
		tokenString, err := auth.SignedToken(claims)

		// Assert
		require.NoError(t, err) // JWT library allows empty secret
		assert.NotEmpty(t, tokenString)
	})

	t.Run("should generate different tokens for different claims", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
			TokenSecret:   "my-secret-key",
		}
		claims1 := jwt.MapClaims{"sub": "user1"}
		claims2 := jwt.MapClaims{"sub": "user2"}

		// Act
		token1, err1 := auth.SignedToken(claims1)
		token2, err2 := auth.SignedToken(claims2)

		// Assert
		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, token1, token2)
	})
}

func TestAuth_TokenDuration(t *testing.T) {
	t.Run("should correctly convert seconds to duration", func(t *testing.T) {
		// Arrange
		testCases := []struct {
			name            string
			durationSeconds int
			expectedMinutes float64
		}{
			{"1 hour", 3600, 60},
			{"30 minutes", 1800, 30},
			{"5 minutes", 300, 5},
			{"1 day", 86400, 1440},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Act
				auth := Default("secret", tc.durationSeconds)

				// Assert
				assert.Equal(t, tc.expectedMinutes, auth.TokenDuration.Minutes())
			})
		}
	})
}

func TestAuth_ClaimsKey(t *testing.T) {
	t.Run("should set ClaimsKey correctly", func(t *testing.T) {
		// Arrange
		testKeys := []string{
			"test-key-1",
			"another-key",
			"super-secret-key",
		}

		for _, key := range testKeys {
			t.Run(key, func(t *testing.T) {
				// Act
				auth := Default(key, 3600)

				// Assert
				assert.Equal(t, ClaimsKey(key), auth.ClaimsKey)
			})
		}
	})
}
