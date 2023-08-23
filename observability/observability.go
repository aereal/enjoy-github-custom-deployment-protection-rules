package observability

import (
	"context"
	"fmt"

	"github.com/aereal/otel-propagators/datadog"
	lambdadetector "go.opentelemetry.io/contrib/detectors/aws/lambda"
	"go.opentelemetry.io/contrib/propagators/aws/xray"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

type setupConfig struct {
	serviceVersion string
}

type SetupOption func(*setupConfig)

func WithServiceVersion(version string) SetupOption {
	return func(sc *setupConfig) { sc.serviceVersion = version }
}

func Setup(ctx context.Context, opts ...SetupOption) (func(context.Context) error, error) {
	var cfg setupConfig
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.serviceVersion == "" {
		cfg.serviceVersion = "unknown"
	}
	exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("otlptracegrpc.New: %w", err)
	}
	res, err := resource.New(ctx,
		resource.WithDetectors(lambdadetector.NewResourceDetector()),
		resource.WithAttributes(
			semconv.ServiceName("enjoy-github-custom-deployment-protection-rules"),
			semconv.ServiceVersion(cfg.serviceVersion),
			semconv.DeploymentEnvironment("local"),
		),
		resource.WithSchemaURL(semconv.SchemaURL))
	if err != nil {
		return nil, fmt.Errorf("resource.New: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(xray.Propagator{}, datadog.Propagator{}))
	return func(ctx context.Context) error { return tp.Shutdown(ctx) }, nil
}
