package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/log"
	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/observability"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda/xrayconfig"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var (
	serviceVersion   string
	exportTraceGrace = time.Second * 3
)

func New() *Handler {
	h := &Handler{
		tracer: otel.GetTracerProvider().Tracer("github.com/aereal/enjoy-github-custom-deployment-protection-rules"),
	}
	return h
}

type Handler struct {
	tracer trace.Tracer
}

func (h *Handler) Handle(ctx context.Context, req events.LambdaFunctionURLRequest) (_ *events.LambdaFunctionURLResponse, err error) {
	ctx, span := h.tracer.Start(ctx, "Handler.Handle", trace.WithTimestamp(time.Unix(req.RequestContext.TimeEpoch/1000, req.RequestContext.TimeEpoch%1000)))
	defer func() {
		code := codes.Ok
		if err != nil {
			code = codes.Error
			span.RecordError(err)
		}
		span.SetStatus(code, "")
		span.End()
	}()
	sc := span.SpanContext()
	logger := log.FromContext(ctx).With(zap.Stringer("trace_id", sc.TraceID()), zap.Stringer("span_id", sc.SpanID()))
	logger.Info("handle request", zap.String("path", req.RawPath))

	return respNotFound, nil
}

var (
	respNotFound = &events.LambdaFunctionURLResponse{
		StatusCode: http.StatusNotFound,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       `{"error":"not found"}`,
	}
)

func Start() int {
	logger, err := log.New()
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"severity": "ERROR", "msg": err.Error(), "time": time.Now().Format("2006-01-02T15:04:05.000Z0700")})
		return 1
	}
	ctx := log.WithLogger(context.Background(), logger)
	defer func() { _ = logger.Sync() }()
	finish, err := observability.Setup(ctx, observability.WithServiceVersion(serviceVersion))
	if err != nil {
		logger.Error("failed to setup OpenTelemetry", zap.Error(err))
		return 1
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), exportTraceGrace)
		defer cancel()
		logger.Debug("start exporting traces", zap.Duration("export_grace", exportTraceGrace))
		if err := finish(ctx); err != nil {
			logger.Warn("failed to export traces")
		}
	}()
	tp := otel.GetTracerProvider()
	opts := []otellambda.Option{
		xrayconfig.WithEventToCarrier(),
		otellambda.WithTracerProvider(tp),
	}
	if flusher, ok := tp.(otellambda.Flusher); ok {
		opts = append(opts, otellambda.WithFlusher(flusher))
	}
	h := New()
	lambda.StartWithOptions(otellambda.InstrumentHandler(h.Handle, opts...), lambda.WithContext(log.WithLogger(context.Background(), logger)))
	return 0
}
