package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	"github.com/ribeirohugo/go_middlewares/pkg/authentication"
)

// GetClaims allows to extract claims from context.
func (j *JWT) GetClaims(ctx context.Context) (authentication.Claims, error) {
	claims, err := j.auth.ParseClaims(ctx)
	if err != nil {
		return authentication.Claims{}, err
	}

	if j.redis != nil {
		_, err = j.redis.Get(ctx, claims.ID).Result()
		if err != nil {
			if err == redis.Nil {
				return authentication.Claims{}, fmt.Errorf("key does not exist: %v", err)
			}

			return authentication.Claims{}, fmt.Errorf("redis error: %v", err)
		}
	}

	return claims, err
}

func (j *JWT) CheckLogin(ctx context.Context) (bool, error) {
	claims, err := j.auth.ParseClaims(ctx)
	if err != nil {
		return false, err
	}

	if j.redis != nil {
		_, err = j.redis.Get(ctx, claims.ID).Result()
		if err != nil {
			if err == redis.Nil {
				return false, fmt.Errorf("key does not exist: %v", err)
			}

			return false, fmt.Errorf("redis error: %v", err)
		}
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != j.auth.SigningMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(j.auth.ClaimsKey), nil
	})

	if claims.ExpiresAt > 0 {
		remainingTTL := time.Until(time.Unix(claims.ExpiresAt, 0))

		if remainingTTL > 0 {
			j.redis.Del(ctx, claims.ID)
			return false, nil
		}
	}

	return false, nil
}

// Logout removes claims from the context, effectively logging the user out.
func (j *JWT) Logout(ctx context.Context) (context.Context, error) {
	if j.redis != nil {
		claims, ok := ctx.Value(j.auth.ClaimsKey).(*authentication.Claims)
		if ok && claims != nil {
			err := j.redis.Del(ctx, claims.ID).Err()
			if err != nil {
				return ctx, fmt.Errorf("redis del error: %v", err)
			}
		}
	}

	return context.WithValue(ctx, j.auth.ClaimsKey, nil), nil
}

func (j *JWT) Login(ctx context.Context, subject, issuer, audience, role string) (string, error) {
	claims := authentication.NewMapClaims(subject, issuer, audience, role, j.auth.TokenDuration)

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
