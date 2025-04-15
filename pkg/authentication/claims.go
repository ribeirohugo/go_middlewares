package authentication

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ClaimsKey is a custom context key for storing JWT claims.
type ClaimsKey string

// Claims is a jwt.MapClaims constructor.
//
// It holds the following attributes:
// Subject "sub" - user ID
// Issuer "iss" - token issuer
// Audience "aud" - intended audience
// ExpiresAt "exp" - expiration time (Unix)
// IssuedAt "iat" - issued at (Unix)
func Claims(subject, issuer, audience, role string, tokenDuration int) jwt.MapClaims {
	return jwt.MapClaims{
		"sub":  subject,
		"iss":  issuer,
		"aud":  audience,
		"exp":  time.Now().Add(time.Duration(tokenDuration) * time.Second).Unix(),
		"iat":  time.Now().Unix(),
		"role": role,
	}
}
