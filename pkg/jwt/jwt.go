package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ribeirohugo/go_middlewares/internal/model"
)

const (
	expiredTokenMessage = "token has expired"
	unauthorizedMessage = "unauthorized"
)

// JWT is a JWTMiddleware that holds authentication data and dependencies.
//
// adminRole is the maximum permission role, that allows everything by default.
// claimsKey is the authentication key used by claims.
// tokenSecret the secret key to verify the integrity and authenticity of the JWT
// tokenMaxAge is the max duration of a token, in nanoseconds.
// skipList is the list of endpoints that are ignored for JWT verification.
// permissionsMap is the list of endpoints, associated to the allowed permission roles.
type JWT struct {
	AdminRole      string
	ClaimsKey      any
	PermissionsMap map[string][]string
	SkipList       []string
	TokenDuration  time.Duration
	TokenSecret    string
}

// New is a JWT middleware constructor.
//
// adminRole is the maximum permission role, that allows everything by default.
// claimsKey is the authentication key used by claims.
// tokenSecret the secret key to verify the integrity and authenticity of the JWT
// tokenMaxAge is the max duration of a token, in nanoseconds.
// skipList is the list of endpoints that are ignored for JWT verification.
// permissionsMap is the list of endpoints, associated to the allowed permission roles.
func New(
	adminRole, tokenSecret string,
	tokenMaxAge int,
	claimsKey any,
	skipList []string,
	permissionsMap map[string][]string,
) JWT {
	return JWT{
		AdminRole:      adminRole,
		ClaimsKey:      claimsKey,
		PermissionsMap: permissionsMap,
		SkipList:       skipList,
		TokenDuration:  time.Duration(tokenMaxAge),
		TokenSecret:    tokenSecret,
	}
}

// Middleware handles JWT authentication in server requests.
func (j *JWT) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		for i := range j.SkipList {
			if strings.HasPrefix(r.URL.Path, j.SkipList[i]) {
				// Skip JWT verification for endpoint requests
				next.ServeHTTP(w, r)
				return
			}
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		if tokenString == "" {
			j.error(w, unauthorizedMessage)
			return
		}

		jwtClaims := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(tokenString, &jwtClaims, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(j.TokenSecret), nil
		})
		if err != nil {
			if err.Error() == "Token is expired" {
				j.error(w, expiredTokenMessage)
				return
			}

			log.Println(err)
			j.error(w, unauthorizedMessage)
			return
		}

		if claims, ok := token.Claims.(*jwt.MapClaims); ok {
			userRole, ok := jwtClaims["role"]
			if ok {
				if j.checkRolePermissions(r, userRole.(string)) {
					// Store the claims in the request context for use in the handler.
					ctx := context.WithValue(r.Context(), j.ClaimsKey, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		j.error(w, unauthorizedMessage)
	})
}

// checkRolePermissions verifies if current user role is allowed to access current URL request
// according to permission mapping previously defined.
func (j *JWT) checkRolePermissions(r *http.Request, userRole string) bool {
	if userRole == j.AdminRole {
		return true
	}

	var (
		hasPrefix = false
		allowed   = false
	)

	for k, roles := range j.PermissionsMap {
		if strings.HasPrefix(r.URL.Path, k) {
			hasPrefix = true

			for i := range roles {
				if roles[i] == userRole {
					allowed = true
					break
				}
			}
		}
	}

	if !hasPrefix {
		allowed = true
	}

	return allowed
}

func (j *JWT) error(w http.ResponseWriter, message string) {
	errorDto := model.Error{
		Message: message,
	}

	errorJSON, err := json.Marshal(errorDto)
	if err != nil {
		log.Println(err)
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	_, err = w.Write(errorJSON)
	if err != nil {
		log.Println(err)
		return
	}
}
