package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/log"
	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/observability"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/google/go-github/v54/github"
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
	respOK           = &events.LambdaFunctionURLResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       `{}`,
	}
	respError = &events.LambdaFunctionURLResponse{
		StatusCode: http.StatusInternalServerError,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       `{"error":"failed"}`,
	}
	respNotFound = &events.LambdaFunctionURLResponse{
		StatusCode: http.StatusNotFound,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       `{"error":"not found"}`,
	}
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
		span.SetStatus(codes.Ok, "")
		span.End()
	}()
	sc := span.SpanContext()
	logger := log.FromContext(ctx).With(zap.Stringer("trace_id", sc.TraceID()), zap.Stringer("span_id", sc.SpanID()))
	ctx = log.WithLogger(ctx, logger)
	defer func() {
		logger.Info("processed request", zap.String("path", req.RawPath))
	}()

	switch req.RawPath {
	case "/webhook":
		if err := h.handleWebhook(ctx, req); err != nil {
			return respError, nil
		}
		return respOK, nil
	default:
		return respNotFound, nil
	}
}

func (h *Handler) handleWebhook(ctx context.Context, req events.LambdaFunctionURLRequest) (err error) {
	ctx, span := h.tracer.Start(ctx, "Handler.handleWebhook")
	defer func() {
		code := codes.Ok
		if err != nil {
			code = codes.Error
			span.RecordError(err)
		}
		span.SetStatus(code, "")
		span.End()
	}()

	payload, err := parseAndValidateWebhookPayload(req, []byte("83a196e5cf55aeaf98e85c1eb08a0c14feb30ae6f7d9a8db79d20b705c7244ef"))
	if err != nil {
		return fmt.Errorf("parseAndValidateWebhookPayload: %w", err)
	}
	logger := log.FromContext(ctx)
	switch payload := payload.(type) {
	case *github.DeploymentProtectionRuleEvent:
		fields := []zap.Field{
			zap.Stringp("environment", payload.Environment),
			zap.Stringp("action", payload.Action),
			zap.Stringp("deployment_callback_url", payload.DeploymentCallbackURL),
		}
		if inst := payload.Installation; inst != nil {
			fields = append(fields,
				zap.Int64p("installation.target_id", inst.TargetID),
				zap.Stringp("installation.target_type", inst.TargetType),
				zap.Int64p("installation.id", inst.ID))
		}
		if sender := payload.Sender; sender != nil {
			fields = append(fields, zap.Stringp("sender.login", sender.Login))
		}
		if deploy := payload.Deployment; deploy != nil {
			fields = append(fields,
				zap.Stringp("deploy.sha", deploy.SHA),
				zap.Stringp("deploy.ref", deploy.Ref),
				zap.Stringp("deploy.task", deploy.Task),
				zap.Stringp("deploy.environment", deploy.Environment),
				zap.Stringp("deploy.description", deploy.Description),
				zap.Int64p("deploy.id", deploy.ID))
		}
		logger.Info("receive deployment_protection_rule event", fields...)
	default:
		logger.Info("receive unknown webhook event", zap.String("github.webhook.go_type", fmt.Sprintf("%T", payload)))
	}

	return nil
}

func parseAndValidateWebhookPayload(req events.LambdaFunctionURLRequest, secret []byte) (any, error) {
	reqHeader := http.Header{}
	for k, v := range req.Headers {
		reqHeader.Add(k, v)
	}
	sig := reqHeader.Get(github.SHA256SignatureHeader)
	if sig == "" {
		sig = reqHeader.Get(github.SHA1SignatureHeader)
	}
	mt, _, err := mime.ParseMediaType(reqHeader.Get("content-type"))
	if err != nil {
		return nil, fmt.Errorf("mime.ParseMediaType: %w", err)
	}

	body := strings.NewReader(req.Body)
	payload, err := github.ValidatePayloadFromBody(mt, body, sig, secret)
	if err != nil {
		return nil, fmt.Errorf("github.ValidatePayloadFromBody: %w", err)
	}
	webhookType := reqHeader.Get(github.EventTypeHeader)
	parsed, err := github.ParseWebHook(webhookType, payload)
	if err != nil {
		return nil, fmt.Errorf("github.ParseWebHook: %w", err)
	}
	return parsed, nil
}

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
