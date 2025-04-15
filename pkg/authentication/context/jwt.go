package jwt

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func (j *JWT) parseClaims(ctx context.Context) (jwt.MapClaims, error) {
	claims, ok := ctx.Value(j.auth.ClaimsKey).(*jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("token not found in context")
	}

	return *claims, nil
}

// GetClaims allows to extract claims from context.
func (j *JWT) GetClaims(ctx context.Context) (jwt.Claims, error) {
	claims, err := j.parseClaims(ctx)
	if err != nil {
		return jwt.MapClaims{}, err
	}

	_, ok := claims["sub"]
	if !ok {
		return jwt.MapClaims{}, fmt.Errorf("user id wasn't found in claims")
	}

	_, ok = claims["role"]
	if !ok {
		return jwt.MapClaims{}, fmt.Errorf("role wasn't found in claims")
	}

	return claims, err
}

// Logout removes claims from the context, effectively logging the user out.
func (j *JWT) Logout(ctx context.Context) context.Context {
	return context.WithValue(ctx, j.auth.ClaimsKey, nil)
}
