package authentication

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ClaimsKey is a custom context key for storing JWT claims.
type ClaimsKey string

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
func NewClaims(subject, issuer, audience, role string, tokenDuration int) Claims {
	return Claims{
		ID:        uuid.NewString(),
		Subject:   subject,
		Issuer:    issuer,
		Audience:  audience,
		Role:      role,
		IssuedAt:  time.Now().Unix(),
		ExpiredAt: time.Now().Add(time.Duration(tokenDuration) * time.Second).Unix(),
	}
}

// Claims defines the JWT payload with standard claims and a custom user role.
type Claims struct {
	ID        string `json:"id"`
	Subject   string `json:"sub"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	ExpiredAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Role      string `json:"role"`
}
