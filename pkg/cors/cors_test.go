package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCORS(t *testing.T) {
	t.Run("Allowed Origin", func(t *testing.T) {
		allowedOrigins := []string{"http://example.com"}
		c := New(allowedOrigins)
		handler := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
		req.Header.Set("Origin", "http://example.com")
		resp := httptest.NewRecorder()

		handler.ServeHTTP(resp, req)
		assert.Equal(t, "http://example.com", resp.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("Disallowed Origin", func(t *testing.T) {
		allowedOrigins := []string{"http://example.com"}
		c := New(allowedOrigins)
		handler := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
		req.Header.Set("Origin", "http://notallowed.com")
		resp := httptest.NewRecorder()

		handler.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusForbidden, resp.Code)
	})

	t.Run("OPTIONS Request", func(t *testing.T) {
		allowedOrigins := []string{"http://example.com"}
		c := New(allowedOrigins)
		handler := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodOptions, "http://localhost", nil)
		req.Header.Set("Origin", "http://example.com")
		resp := httptest.NewRecorder()

		handler.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusOK, resp.Code)
	})

	t.Run("Wildcard Allowed When No Allowed Origins Configured", func(t *testing.T) {
		c := New([]string{}) // No allowed origins set
		handler := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
		req.Header.Set("Origin", "http://random.com")
		resp := httptest.NewRecorder()

		handler.ServeHTTP(resp, req)
		assert.Equal(t, "*", resp.Header().Get("Access-Control-Allow-Origin"))
	})
}
