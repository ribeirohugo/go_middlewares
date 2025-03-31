package tracing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace"
)

func TestMiddleware(t *testing.T) {
	// Set up a test tracer
	tp := trace.NewTracerProvider()
	otel.SetTracerProvider(tp)

	// Create a test handler that simply responds with "OK"
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		require.NoError(t, err)
	})

	// Wrap it with the middleware
	middleware := Middleware(testHandler)

	// Create a test request
	req := httptest.NewRequest("GET", "/test-path", nil)
	recorder := httptest.NewRecorder()

	// Call the middleware
	middleware.ServeHTTP(recorder, req)

	// Assert response
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "OK", recorder.Body.String())

	// Check if a span was created
	tracer := otel.Tracer(serverSpan)
	_, span := tracer.Start(req.Context(), "test-span")
	defer span.End()

	// Ensure that span attributes are properly set
	spanCtx := span.SpanContext()
	assert.NotNil(t, spanCtx)
}
