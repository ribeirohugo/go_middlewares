package cors

import "net/http"

// CORS holds CORS middleware dependencies and related methods.
type CORS struct {
	allowedOrigins []string
}

// New is a CORS middleware constructor.
func New(allowedOrigins []string) CORS {
	return CORS{
		allowedOrigins: allowedOrigins,
	}
}

// Middleware is responsible to handle CORS allowance
func (c CORS) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// If no allowed origins are set, allow all (*)
		if len(c.allowedOrigins) == 0 {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			allowed := false

			for _, allowedOrigin := range c.allowedOrigins {
				if allowedOrigin == origin {
					allowed = true
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}

			if !allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
