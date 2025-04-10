package authentication

import "github.com/golang-jwt/jwt/v5"

// Auth is responsible for common operations with authentication and JWT.
type Auth struct {
	token     string
	claimsKey ClaimsKey
}

// New is an Auth constructor.
func New(token, key string) Auth {
	return Auth{
		token:     token,
		claimsKey: ClaimsKey(key),
	}
}

func Login(secret string, method jwt.SigningMethod, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(method, claims)

	return token.SignedString([]byte(secret))
}

func (a Auth) ClaimsKey() ClaimsKey {
	return a.claimsKey
}
