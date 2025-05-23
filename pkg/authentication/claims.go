package authentication

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ClaimsKey is a custom context key for storing JWT claims.
type ClaimsKey string

// Claims defines the JWT payload with standard claims and a custom user role.
type Claims struct {
	ID        string `json:"id"`
	Subject   string `json:"sub"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Role      string `json:"role"`
}

// NewMapClaims is a jwt.MapClaims constructor.
//
// It holds the following attributes:
// Subject "sub" - user ID
// Issuer "iss" - token issuer
// Audience "aud" - intended audience
// ExpiresAt "exp" - expiration time (Unix)
// IssuedAt "iat" - issued at (Unix)
func NewMapClaims(subject, issuer, audience, role string, tokenDuration time.Duration) jwt.MapClaims {
	return jwt.MapClaims{
		"id":   uuid.New().String(),
		"sub":  subject,
		"iss":  issuer,
		"aud":  audience,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(tokenDuration).Unix(),
		"role": role,
	}
}

// NewClaims is a jwt.MapClaims constructor.
//
// It holds the following attributes:
// Subject "sub" - user ID
// Issuer "iss" - token issuer
// Audience "aud" - intended audience
// ExpiresAt "exp" - expiration time (Unix)
// IssuedAt "iat" - issued at (Unix)
func NewClaims(subject, issuer, audience, role string, tokenDuration time.Duration) Claims {
	return Claims{
		ID:        uuid.NewString(),
		Subject:   subject,
		Issuer:    issuer,
		Audience:  audience,
		Role:      role,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(tokenDuration * time.Second).Unix(),
	}
}

// ClaimsSignedToken SignedToken generates and signs a JWT using the provided secret and claims.
func (a *Auth) ClaimsSignedToken(subject, issuer, audience, role string) (string, error) {
	claims := NewMapClaims(subject, issuer, audience, role, a.TokenDuration)

	token := jwt.NewWithClaims(a.SigningMethod, claims)

	return token.SignedString([]byte(a.ClaimsKey))
}

func (a *Auth) ParseClaims(ctx context.Context) (Claims, error) {
	ptrClaims, ok := ctx.Value(a.ClaimsKey).(*jwt.MapClaims)
	if !ok {
		return Claims{}, fmt.Errorf("token not found in context")
	}

	claims := *ptrClaims

	sub, err := claims.GetSubject()
	if err != nil {
		return Claims{}, fmt.Errorf("subject  wasn't found in claims")
	}

	id, ok := claims["id"]
	if !ok {
		return Claims{}, fmt.Errorf("id wasn't found in claims")
	}

	role, ok := claims["role"]
	if !ok {
		return Claims{}, fmt.Errorf("role wasn't found in claims")
	}

	issuer, err := claims.GetIssuer()
	if err != nil {
		return Claims{}, fmt.Errorf("issuer wasn't found in claims")
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return Claims{}, fmt.Errorf("issuer wasn't found in claims")
	}

	expirationTime, err := claims.GetExpirationTime()
	if err != nil {
		return Claims{}, fmt.Errorf("issuer wasn't found in claims")
	}

	authClaims := Claims{
		ID:        id.(string),
		Subject:   sub,
		Role:      role.(string),
		Issuer:    issuer,
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: expirationTime.Unix(),
	}

	return authClaims, nil
}
