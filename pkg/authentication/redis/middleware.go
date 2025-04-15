package jwt

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/ribeirohugo/go_middlewares/internal/model"
)

// Middleware handles JWT authentication with Redis caching.
func (j *JWT) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, skip := range j.SkipList {
			if strings.HasPrefix(r.URL.Path, skip) {
				next.ServeHTTP(w, r)
				return
			}
		}

		authHeader := r.Header.Get("Authorization")
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			j.error(w, unauthorizedMessage)
			return
		}

		ctx := r.Context()

		claims, err := j.auth.ParseClaims(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "expired") {
				j.error(w, expiredTokenMessage)
			} else {
				log.Println("JWT parse error:", err)
				j.error(w, unauthorizedMessage)
			}
			return
		}

		if j.checkRolePermissions(r, claims.Role) {
			ctx := context.WithValue(r.Context(), j.ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		j.error(w, unauthorizedMessage)
	})
}

func (j *JWT) checkRolePermissions(r *http.Request, userRole string) bool {
	if userRole == j.AdminRole {
		return true
	}

	hasPrefix := false
	allowed := false

	for k, roles := range j.PermissionsMap {
		if strings.HasPrefix(r.URL.Path, k) {
			hasPrefix = true
			for _, role := range roles {
				if role == userRole {
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
		log.Println("JSON marshal error:", err)
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	if _, err := w.Write(errorJSON); err != nil {
		log.Println("Write error:", err)
	}
}
