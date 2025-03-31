package provider

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger" //nolint:staticcheck // TODO: remove jaeger exporter
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
)

// Jaeger returns an OpenTelemetry TracerProvider configured to use the Jaeger exporter
// that will send spans to the provided url. The returned Provider will also use a Resource
// configured with all the information about the application.
func Jaeger(url, environment, service string) (*trace.TracerProvider, error) {
	// Create the Jaeger exporter
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(url)))
	if err != nil {
		return nil, err
	}

	tp := trace.NewTracerProvider(
		// Always be sure to batch in production.
		trace.WithBatcher(exp),
		// Record information about this application in a Resource.
		trace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(service),
			attribute.String("environment", environment),
		)),
	)

	// Register TracerProvider as the global so any imported
	// instrumentation in the future will default to using it.
	otel.SetTracerProvider(tp)

	return tp, nil
}
