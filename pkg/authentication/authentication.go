package authentication

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Auth is responsible for common operations with authentication and JWT.
type Auth struct {
	ClaimsKey     ClaimsKey
	SigningMethod jwt.SigningMethod
	TokenDuration time.Duration
	TokenSecret   string
}

// Authentication interface is the abstraction for authentication layer methods.
type Authentication interface {
	GetClaims(ctx context.Context) (Claims, error)
	Logout(ctx context.Context) context.Context
	Login(ctx context.Context, subject, issuer, audience, role string) (string, error)
}

// New is an Auth constructor.
func New(token string, tokenDuration int, method jwt.SigningMethod) Auth {
	return Auth{
		ClaimsKey:     ClaimsKey(token),
		SigningMethod: method,
		TokenDuration: time.Duration(tokenDuration) * time.Second,
	}
}

// Default is an Auth constructor without default.
func Default(token string, tokenDuration int) Auth {
	return Auth{
		ClaimsKey:     ClaimsKey(token),
		TokenDuration: time.Duration(tokenDuration) * time.Second,
		SigningMethod: jwt.SigningMethodHS256,
	}
}

// SignedToken generates and signs a JWT using the provided secret and claims.
func (a *Auth) SignedToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(a.SigningMethod, claims)

	return token.SignedString([]byte(a.TokenSecret))
}
