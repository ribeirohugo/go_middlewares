package prometheus

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Define Prometheus metrics
var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests received",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Histogram of response time for HTTP requests",
			Buckets: prometheus.DefBuckets, // Default latency buckets
		},
		[]string{"method", "path"},
	)
)

// Prometheus holds Prometheus middleware dependencies and related methods.
type Prometheus struct {
	service string
	token   string
}

// NewPrometheus is a Prometheus middleware constructor.
func NewPrometheus(service, token string) Prometheus {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)

	return Prometheus{
		token:   token,
		service: service,
	}
}

// Handler method for /metrics with token authentication
func (p Prometheus) Handler(w http.ResponseWriter, r *http.Request) {
	// Extract Authorization header
	authHeader := r.Header.Get("Authorization")

	// Validate Bearer Token
	if p.token != "" &&
		(!strings.HasPrefix(authHeader, "Bearer ") ||
			strings.TrimPrefix(authHeader, "Bearer ") != p.token) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Token is valid, serve Prometheus metrics
	promhttp.Handler().ServeHTTP(w, r)
}

func (p Prometheus) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Capture response status
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(recorder, r)

		duration := time.Since(start).Seconds()

		// Record metrics
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(recorder.statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	})
}

// statusRecorder helps capture the HTTP status code
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}
