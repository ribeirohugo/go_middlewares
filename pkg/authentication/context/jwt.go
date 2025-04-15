package jwt

import (
	"context"
	"fmt"
	"github.com/ribeirohugo/go_middlewares/pkg/authentication"

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
func (j *JWT) GetClaims(ctx context.Context) (authentication.Claims, error) {
	claims, err := j.parseClaims(ctx)
	if err != nil {
		return authentication.Claims{}, err
	}

	sub, ok := claims["sub"]
	if !ok {
		return authentication.Claims{}, fmt.Errorf("user id wasn't found in claims")
	}

	role, ok := claims["role"]
	if !ok {
		return authentication.Claims{}, fmt.Errorf("role wasn't found in claims")
	}

	issuer, ok := claims["iss"]
	if !ok {
		issuer = ""
	}

	audience, ok := claims["iss"]
	if !ok {
		audience = ""
	}

	authClaims := authentication.Claims{
		Subject:  sub.(string),
		Role:     role.(string),
		Issuer:   issuer.(string),
		Audience: audience.(string),
	}

	return authClaims, err
}

// Logout removes claims from the context, effectively logging the user out.
func (j *JWT) Logout(ctx context.Context) context.Context {
	return context.WithValue(ctx, j.auth.ClaimsKey, nil)
}
