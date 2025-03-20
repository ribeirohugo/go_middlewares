package tracing

import (
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

const (
	serverSpan = "server-request"
)

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		componentName := generateComponentName(r)

		// Use the global TracerProvider.
		tr := otel.Tracer(serverSpan)

		ctx, span := tr.Start(ctx, componentName)
		defer span.End()

		span.SetAttributes(
			attribute.Key("method").String(r.Method),
			attribute.Key("url").String(r.URL.String()),
			attribute.Key("remote-address").String(r.RemoteAddr),
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func generateComponentName(r *http.Request) string {
	return fmt.Sprintf("%s %s", r.Method, r.URL.Path)
}
