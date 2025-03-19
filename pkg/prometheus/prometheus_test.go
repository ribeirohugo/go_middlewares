package prometheus

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func unregisterMetrics(t *testing.T) {
	t.Helper()

	prometheus.Unregister(httpRequestsTotal)
	prometheus.Unregister(httpRequestDuration)
}

func TestHandler_Unauthorized(t *testing.T) {
	p := NewPrometheus("test-service", "valid-token")

	r := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	p.Handler(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)

	unregisterMetrics(t)
}

func TestHandler_Authorized(t *testing.T) {
	p := NewPrometheus("test-service", "valid-token")

	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	p.Handler(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	unregisterMetrics(t)
}

func TestMiddleware_MetricsRecorded(t *testing.T) {
	p := NewPrometheus("test-service", "")

	handler := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	unregisterMetrics(t)
}
