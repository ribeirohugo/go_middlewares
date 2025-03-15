package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ribeirohugo/go_middlewares/internal/model"

	"github.com/golang-jwt/jwt/v5"
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
	adminRole      string
	claimsKeys     string
	permissionsMap map[string][]string
	skipList       []string
	tokenDuration  time.Duration
	tokenSecret    string
}

// NewJWT is a JWT middleware constructor.
//
// adminRole is the maximum permission role, that allows everything by default.
// claimsKey is the authentication key used by claims.
// tokenSecret the secret key to verify the integrity and authenticity of the JWT
// tokenMaxAge is the max duration of a token, in nanoseconds.
// skipList is the list of endpoints that are ignored for JWT verification.
// permissionsMap is the list of endpoints, associated to the allowed permission roles.
func NewJWT(
	adminRole, claimsKey, tokenSecret string,
	tokenMaxAge int64,
	skipList []string,
	permissionsMap map[string][]string,
) JWT {
	return JWT{
		adminRole:      adminRole,
		claimsKeys:     claimsKey,
		permissionsMap: permissionsMap,
		skipList:       skipList,
		tokenDuration:  time.Duration(tokenMaxAge),
		tokenSecret:    tokenSecret,
	}
}

// Middleware handles JWT authentication in server requests.
func (j *JWT) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		for i := range j.skipList {
			if strings.HasPrefix(r.URL.Path, j.skipList[i]) {
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

		token, err := jwt.ParseWithClaims(tokenString, &jwtClaims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(j.tokenSecret), nil
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
					ctx := context.WithValue(r.Context(), j.claimsKeys, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		j.error(w, "Unauthorized")
	})
}

// checkRolePermissions verifies if current user role is allowed to access current URL request
// according to permission mapping previously defined.
func (j *JWT) checkRolePermissions(r *http.Request, userRole string) bool {
	if userRole == j.adminRole {
		return true
	}

	var (
		hasPrefix = false
		allowed   = false
	)

	for k, roles := range j.permissionsMap {
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
