// Package redis holds Redis auth middleware.
package redis

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	jwtAuth "github.com/ribeirohugo/go_middlewares/pkg/jwt"
)

// GetClaims allows to extract claims from context.
func (j *JWT) GetClaims(ctx context.Context) (jwtAuth.Claims, error) {
	claims, err := j.auth.ParseClaims(ctx)
	if err != nil {
		return jwtAuth.Claims{}, err
	}

	if j.redis != nil {
		_, err = j.redis.Get(ctx, claims.ID).Result()
		if err != nil {
			if err == redis.Nil {
				return jwtAuth.Claims{}, fmt.Errorf("key does not exist: %v", err)
			}

			return jwtAuth.Claims{}, fmt.Errorf("redis error: %v", err)
		}
	}

	return claims, err
}

// Logout removes claims from the context, effectively logging the user out.
func (j *JWT) Logout(ctx context.Context) (context.Context, error) {
	if j.redis != nil {
		claims, err := j.GetClaims(ctx)
		if err != nil {
			return ctx, err
		}

		j.redis.Del(ctx, claims.ID)
	}

	return context.WithValue(ctx, j.auth.ClaimsKey, nil), nil
}

// Login creates and signs a JWT with the provided claims, optionally storing
// the token in Redis using the claim ID as the key.
func (j *JWT) Login(ctx context.Context, subject, issuer, audience, role string) (string, error) {
	claims := jwtAuth.NewMapClaims(subject, issuer, audience, role, j.auth.TokenDuration)

	token := jwt.NewWithClaims(j.auth.SigningMethod, claims)

	tokenString, err := token.SignedString([]byte(j.auth.ClaimsKey))
	if err != nil {
		return "", fmt.Errorf("signing claims token failed: %v", err)
	}

	if j.redis != nil {
		err = j.redis.Set(ctx, claims["id"].(string), tokenString, j.auth.TokenDuration).Err()
		if err != nil {
			return "", fmt.Errorf("redis set failed: %v", err)
		}
	}

	return tokenString, nil
}
