package jwt

import (
	"context"
	"fmt"

	"github.com/ribeirohugo/go_middlewares/pkg/authentication"
)

// GetClaims allows to extract claims from context.
func (j *JWT) GetClaims(ctx context.Context) (authentication.Claims, error) {
	return j.auth.ParseClaims(ctx)
}

// Logout removes claims from the context, effectively logging the user out.
func (j *JWT) Logout(ctx context.Context) context.Context {
	return context.WithValue(ctx, j.auth.ClaimsKey, nil)
}

func (j *JWT) Login(_ context.Context, subject, issuer, audience, role string) (string, error) {
	tokenString, err := j.auth.ClaimsSignedToken(subject, issuer, audience, role)
	if err != nil {
		return "", fmt.Errorf("login failed: %v", err)
	}

	return tokenString, err
}
