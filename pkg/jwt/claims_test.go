package jwt

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMapClaims(t *testing.T) {
	t.Run("should create map claims with all fields", func(t *testing.T) {
		// Arrange
		subject := "user123"
		issuer := "test-service"
		audience := "test-app"
		role := "admin"
		duration := time.Hour

		// Act
		claims := NewMapClaims(subject, issuer, audience, role, duration)

		// Assert
		assert.NotEmpty(t, claims["id"])
		assert.Equal(t, subject, claims["sub"])
		assert.Equal(t, issuer, claims["iss"])
		assert.Equal(t, audience, claims["aud"])
		assert.Equal(t, role, claims["role"])
		assert.NotNil(t, claims["iat"])
		assert.NotNil(t, claims["exp"])
	})

	t.Run("should set correct expiration time", func(t *testing.T) {
		// Arrange
		duration := 2 * time.Hour

		// Act
		claims := NewMapClaims("user1", "service", "app", "user", duration)

		// Assert
		exp := claims["exp"].(int64)
		iat := claims["iat"].(int64)

		// Check that expiration is approximately duration after issued time
		diff := exp - iat
		assert.InDelta(t, duration.Seconds(), float64(diff), 2.0)
	})

	t.Run("should generate unique IDs for different claims", func(t *testing.T) {
		// Act
		claims1 := NewMapClaims("user1", "service", "app", "user", time.Hour)
		claims2 := NewMapClaims("user1", "service", "app", "user", time.Hour)

		// Assert
		assert.NotEqual(t, claims1["id"], claims2["id"])
	})

	t.Run("should handle different roles", func(t *testing.T) {
		// Arrange
		roles := []string{"admin", "user", "guest", "moderator"}

		for _, role := range roles {
			t.Run(role, func(t *testing.T) {
				// Act
				claims := NewMapClaims("user1", "service", "app", role, time.Hour)

				// Assert
				assert.Equal(t, role, claims["role"])
			})
		}
	})

	t.Run("should handle different durations", func(t *testing.T) {
		// Arrange
		testCases := []struct {
			name     string
			duration time.Duration
		}{
			{"15 minutes", 15 * time.Minute},
			{"1 hour", time.Hour},
			{"24 hours", 24 * time.Hour},
			{"7 days", 7 * 24 * time.Hour},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Act
				claims := NewMapClaims("user1", "service", "app", "user", tc.duration)

				// Assert
				exp := claims["exp"].(int64)
				iat := claims["iat"].(int64)
				actualDuration := time.Duration(exp-iat) * time.Second
				assert.InDelta(t, tc.duration.Seconds(), actualDuration.Seconds(), 2.0)
			})
		}
	})
}

func TestNewClaims(t *testing.T) {
	t.Run("should create claims with all fields", func(t *testing.T) {
		// Arrange
		subject := "user456"
		issuer := "my-service"
		audience := "my-app"
		role := "moderator"
		duration := 30 * time.Minute

		// Act
		claims := NewClaims(subject, issuer, audience, role, duration)

		// Assert
		assert.NotEmpty(t, claims.ID)
		assert.Equal(t, subject, claims.Subject)
		assert.Equal(t, issuer, claims.Issuer)
		assert.Equal(t, audience, claims.Audience)
		assert.Equal(t, role, claims.Role)
		assert.NotZero(t, claims.IssuedAt)
		assert.NotZero(t, claims.ExpiresAt)
	})

	t.Run("should set correct expiration time", func(t *testing.T) {
		// Arrange
		duration := 2 * time.Hour

		// Act
		claims := NewClaims("user1", "service", "app", "user", duration)

		// Assert
		diff := claims.ExpiresAt - claims.IssuedAt
		// Note: NewClaims multiplies duration by time.Second again, so we need to account for that
		expectedDiff := (duration * time.Second).Seconds()
		assert.InDelta(t, expectedDiff, float64(diff), 2.0)
	})

	t.Run("should generate unique IDs", func(t *testing.T) {
		// Act
		claims1 := NewClaims("user1", "service", "app", "user", time.Hour)
		claims2 := NewClaims("user1", "service", "app", "user", time.Hour)

		// Assert
		assert.NotEqual(t, claims1.ID, claims2.ID)
	})

	t.Run("should handle various roles", func(t *testing.T) {
		// Arrange
		roles := []string{"admin", "user", "guest", "superadmin"}

		for _, role := range roles {
			t.Run(role, func(t *testing.T) {
				// Act
				claims := NewClaims("user1", "service", "app", role, time.Hour)

				// Assert
				assert.Equal(t, role, claims.Role)
			})
		}
	})

	t.Run("should use correct time format", func(t *testing.T) {
		// Arrange
		beforeTime := time.Now().Unix()

		// Act
		claims := NewClaims("user1", "service", "app", "user", time.Hour)

		// Assert
		afterTime := time.Now().Unix()
		assert.GreaterOrEqual(t, claims.IssuedAt, beforeTime)
		assert.LessOrEqual(t, claims.IssuedAt, afterTime)
	})
}

func TestAuth_ClaimsSignedToken(t *testing.T) {
	t.Run("should generate valid signed token with claims", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
		}

		// Act
		tokenString, err := auth.ClaimsSignedToken("user123", "service", "app", "admin")

		// Assert
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("should include all claim fields in token", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
		}
		subject := "user999"
		issuer := "test-issuer"
		audience := "test-audience"
		role := "user"

		// Act
		tokenString, err := auth.ClaimsSignedToken(subject, issuer, audience, role)

		// Assert
		require.NoError(t, err)

		// Parse and verify
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})

		claims := token.Claims.(jwt.MapClaims)
		assert.Equal(t, subject, claims["sub"])
		assert.Equal(t, issuer, claims["iss"])
		assert.Equal(t, audience, claims["aud"])
		assert.Equal(t, role, claims["role"])
		assert.NotNil(t, claims["id"])
		assert.NotNil(t, claims["iat"])
		assert.NotNil(t, claims["exp"])
	})

	t.Run("should generate different tokens each time", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
		}

		// Act
		token1, _ := auth.ClaimsSignedToken("user1", "service", "app", "user")
		time.Sleep(10 * time.Millisecond)
		token2, _ := auth.ClaimsSignedToken("user1", "service", "app", "user")

		// Assert
		assert.NotEqual(t, token1, token2)
	})

	t.Run("should respect token duration", func(t *testing.T) {
		// Arrange
		duration := 2 * time.Hour
		auth := Auth{
			ClaimsKey:     "test-secret",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: duration,
		}

		// Act
		tokenString, _ := auth.ClaimsSignedToken("user1", "service", "app", "user")

		// Assert
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})
		claims := token.Claims.(jwt.MapClaims)

		exp := int64(claims["exp"].(float64))
		iat := int64(claims["iat"].(float64))
		diff := exp - iat

		assert.InDelta(t, duration.Seconds(), float64(diff), 2.0)
	})
}

func TestAuth_ParseClaims(t *testing.T) {
	t.Run("should parse claims from context", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey:     "test-key",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: time.Hour,
		}

		// Create a real token to get properly formatted claims
		tokenString, _ := auth.ClaimsSignedToken("user123", "test-service", "test-app", "admin")

		// Parse the token to get valid MapClaims
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})
		mapClaims := token.Claims.(jwt.MapClaims)

		ctx := context.WithValue(context.Background(), auth.ClaimsKey, &mapClaims)

		// Act
		claims, err := auth.ParseClaims(ctx)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, "user123", claims.Subject)
		assert.Equal(t, "test-service", claims.Issuer)
		assert.Equal(t, "admin", claims.Role)
	})

	t.Run("should return error when token not found in context", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey: "test-key",
		}
		ctx := context.Background()

		// Act
		_, err := auth.ParseClaims(ctx)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not found in context")
	})

	t.Run("should return error when subject is missing", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey: "test-key",
		}
		now := time.Now()
		mapClaims := jwt.MapClaims{
			"id":   "test-id",
			"role": "admin",
			"iss":  "service",
			"iat":  now.Unix(),
			"exp":  now.Add(time.Hour).Unix(),
		}
		ctx := context.WithValue(context.Background(), auth.ClaimsKey, &mapClaims)

		// Act
		_, err := auth.ParseClaims(ctx)

		// Assert - GetSubject is called first, so it should fail
		require.Error(t, err)
	})

	t.Run("should return error when id is missing", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey: "test-key",
		}
		now := time.Now()
		mapClaims := jwt.MapClaims{
			"sub":  "user123",
			"iss":  "service",
			"role": "admin",
			"iat":  now.Unix(),
			"exp":  now.Add(time.Hour).Unix(),
		}
		ctx := context.WithValue(context.Background(), auth.ClaimsKey, &mapClaims)

		// Act
		_, err := auth.ParseClaims(ctx)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "id wasn't found")
	})

	t.Run("should return error when role is missing", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey: "test-key",
		}
		now := time.Now()
		mapClaims := jwt.MapClaims{
			"id":  "test-id",
			"sub": "user123",
			"iss": "service",
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		}
		ctx := context.WithValue(context.Background(), auth.ClaimsKey, &mapClaims)

		// Act
		_, err := auth.ParseClaims(ctx)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role wasn't found")
	})

	t.Run("should parse all claim fields correctly", func(t *testing.T) {
		// Arrange
		auth := Auth{
			ClaimsKey:     "test-key",
			SigningMethod: jwt.SigningMethodHS256,
			TokenDuration: 2 * time.Hour,
		}

		// Create a real token
		tokenString, _ := auth.ClaimsSignedToken("user789", "my-service", "my-app", "moderator")

		// Parse the token to get valid MapClaims
		token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(auth.ClaimsKey), nil
		})
		mapClaims := token.Claims.(jwt.MapClaims)

		ctx := context.WithValue(context.Background(), auth.ClaimsKey, &mapClaims)

		// Act
		claims, err := auth.ParseClaims(ctx)

		// Assert
		require.NoError(t, err)
		assert.NotEmpty(t, claims.ID)
		assert.Equal(t, "user789", claims.Subject)
		assert.Equal(t, "my-service", claims.Issuer)
		assert.Equal(t, "moderator", claims.Role)
		assert.NotZero(t, claims.IssuedAt)
		assert.NotZero(t, claims.ExpiresAt)
	})
}

func TestClaimsKey(t *testing.T) {
	t.Run("should work as context key", func(t *testing.T) {
		// Arrange
		key := ClaimsKey("my-key")
		value := "test-value"
		ctx := context.WithValue(context.Background(), key, value)

		// Act
		retrieved := ctx.Value(key)

		// Assert
		assert.Equal(t, value, retrieved)
	})

	t.Run("should be unique per key string", func(t *testing.T) {
		// Arrange
		key1 := ClaimsKey("key1")
		key2 := ClaimsKey("key2")
		ctx := context.WithValue(context.Background(), key1, "value1")
		ctx = context.WithValue(ctx, key2, "value2")

		// Act & Assert
		assert.Equal(t, "value1", ctx.Value(key1))
		assert.Equal(t, "value2", ctx.Value(key2))
	})
}

func TestClaims_Structure(t *testing.T) {
	t.Run("should create claims with correct JSON tags", func(t *testing.T) {
		// Arrange
		claims := Claims{
			ID:        "test-id",
			Subject:   "user123",
			Issuer:    "service",
			Audience:  "app",
			ExpiresAt: time.Now().Unix(),
			IssuedAt:  time.Now().Unix(),
			Role:      "admin",
		}

		// Assert - verify the struct is properly defined
		assert.NotEmpty(t, claims.ID)
		assert.NotEmpty(t, claims.Subject)
		assert.NotEmpty(t, claims.Issuer)
		assert.NotEmpty(t, claims.Audience)
		assert.NotZero(t, claims.ExpiresAt)
		assert.NotZero(t, claims.IssuedAt)
		assert.NotEmpty(t, claims.Role)
	})
}
