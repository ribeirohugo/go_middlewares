package provider

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
)

// Tempo returns an OpenTelemetry TracerProvider configured to use the OTLP exporter
// that will send spans to the provided Tempo endpoint.
func Tempo(ctx context.Context, url, environment, service string, secure bool) (*trace.TracerProvider, error) {
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(url)}
	if !secure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(service),
			attribute.String("environment", environment),
		)),
	)

	otel.SetTracerProvider(tp)

	return tp, nil
}
