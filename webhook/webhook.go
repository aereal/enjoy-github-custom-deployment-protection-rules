package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/approvalreq"
	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/log"
	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/observability"
	"github.com/aereal/paramsenc"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/bradleyfalzon/ghinstallation"
	"github.com/google/go-github/v54/github"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda/xrayconfig"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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

	ErrParameterPathPrefixIsEmpty = errors.New("PARAMETER_PATH_PREFIX is empty")
	ErrFunctionURLOriginRequired  = errors.New("FUNCTION_URL_ORIGIN is required")
)

func New() *Handler {
	h := &Handler{
		tracer:              otel.GetTracerProvider().Tracer("github.com/aereal/enjoy-github-custom-deployment-protection-rules"),
		parameterPathPrefix: os.Getenv("PARAMETER_PATH_PREFIX"),
	}
	return h
}

type Handler struct {
	tracer              trace.Tracer
	initMux             sync.Mutex
	hasInitialized      bool
	parameterPathPrefix string
	params              parameters
	ghAppID             int64
	fnURLOrigin         string
	approvalVerifier    *approvalreq.ApprovalVerifier
}

type parameters struct {
	WebhookSecret         string `ssmp:"/webhook_secret"`
	GitHubAppPrivateKey   string `ssmp:"/github_app_private_key"`
	TokenSigningKeyString string `ssmp:"/token_signing_key"`

	tokenSigningKey jwk.Key
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

	if err := h.initialize(ctx); err != nil {
		return respError, nil
	}
	switch req.RawPath {
	case "/webhook":
		if err := h.handleWebhook(ctx, req); err != nil {
			return respError, nil
		}
		return respOK, nil
	case "/approval":
		redirectURL, err := h.handleApproval(ctx, req)
		if err != nil {
			return respError, nil
		}
		return &events.LambdaFunctionURLResponse{
			StatusCode: http.StatusSeeOther,
			Headers: map[string]string{
				"location":     redirectURL,
				"content-type": "text/plain; charset=utf-8",
			},
			Body: fmt.Sprintf("redirect to %s\n", redirectURL),
		}, nil
	default:
		return respNotFound, nil
	}
}

func (h *Handler) initialize(ctx context.Context) (err error) {
	h.initMux.Lock()
	defer h.initMux.Unlock()
	if h.hasInitialized {
		return nil
	}

	ctx, span := h.tracer.Start(ctx, "Handler.initialize")
	defer func() {
		code := codes.Ok
		if err != nil {
			code = codes.Error
			span.RecordError(err)
		}
		span.SetStatus(code, "")
		span.End()
	}()

	h.hasInitialized = true
	if h.parameterPathPrefix == "" {
		return ErrParameterPathPrefixIsEmpty
	}
	h.ghAppID, err = strconv.ParseInt(os.Getenv("GH_APP_ID"), 10, 64)
	if err != nil {
		return fmt.Errorf("strconv.ParseInt: %w", err)
	}
	h.fnURLOrigin = os.Getenv("FUNCTION_URL_ORIGIN")
	if h.fnURLOrigin == "" {
		return ErrFunctionURLOriginRequired
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("config.LoadDefaultConfig: %w", err)
	}
	otelaws.AppendMiddlewares(&cfg.APIOptions)
	client := ssm.NewFromConfig(cfg)
	input := &ssm.GetParametersByPathInput{
		Path:           &h.parameterPathPrefix,
		Recursive:      ref(true),
		WithDecryption: ref(true),
	}
	out, err := client.GetParametersByPath(ctx, input)
	if err != nil {
		return fmt.Errorf("ssm.Client.GetParametersByPath: %w", err)
	}
	if err := paramsenc.NewDecoder(out.Parameters, paramsenc.WithPathPrefix(h.parameterPathPrefix)).Decode(&h.params); err != nil {
		return fmt.Errorf("paramsenc.Decoder.Decode: %w", err)
	}

	tokenSigningKey, err := jwk.ParseKey([]byte(h.params.TokenSigningKeyString), jwk.WithPEM(true))
	if err != nil {
		return fmt.Errorf("jwk.ParseKey: %w", err)
	}
	h.approvalVerifier = approvalreq.NewApprovalVerifier(approvalreq.WithSigningKey(tokenSigningKey))
	return nil
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

	payload, err := parseAndValidateWebhookPayload(req, []byte(h.params.WebhookSecret))
	if err != nil {
		return fmt.Errorf("parseAndValidateWebhookPayload: %w", err)
	}
	logger := log.FromContext(ctx)
	switch payload := payload.(type) {
	case *github.PingEvent, *github.InstallationEvent, *github.InstallationRepositoriesEvent, *github.InstallationTargetEvent:
		// noop
		return nil
	case *github.DeploymentProtectionRuleEvent:
		callbackURL := payload.GetDeploymentCallbackURL()
		installationID := payload.GetInstallation().GetID()
		deployEnv := payload.GetDeployment().GetEnvironment()
		logger.Info("receive deployment_protection_rule event",
			zap.String("environment", payload.GetEnvironment()),
			zap.String("action", payload.GetAction()),
			zap.String("deployment_callback_url", callbackURL),
			zap.Int64("installation.target_id", payload.GetInstallation().GetTargetID()),
			zap.Int64("installation.id", installationID),
			zap.String("installation.target_type", payload.GetInstallation().GetTargetType()),
			zap.String("sender.login", payload.GetSender().GetLogin()),
			zap.String("deploy.sha", payload.GetDeployment().GetSHA()),
			zap.String("deploy.ref", payload.GetDeployment().GetRef()),
			zap.String("deploy.task", payload.GetDeployment().GetTask()),
			zap.String("deploy.environment", payload.GetDeployment().GetEnvironment()),
			zap.String("deploy.description", payload.GetDeployment().GetDescription()),
			zap.Int64("deploy.id", payload.GetDeployment().GetID()),
		)
		tr, err := ghinstallation.New(otelhttp.NewTransport(nil), h.ghAppID, installationID, []byte(h.params.GitHubAppPrivateKey))
		if err != nil {
			return fmt.Errorf("ghinstallation.New: %w", err)
		}
		approvalClaims, err := NewClaimsFromDeploymentProtectionRuleEvent(payload)
		if err != nil {
			return fmt.Errorf("NewClaimsFromDeploymentProtectionRuleEvent: %w", err)
		}
		token, err := h.approvalVerifier.IssueToken(ctx, approvalClaims)
		if err != nil {
			return fmt.Errorf("ApprovalVerifier.IssueToken: %w", err)
		}
		approvalURL, err := url.Parse(h.fnURLOrigin)
		if err != nil {
			return fmt.Errorf("url.Parse: %w", err)
		}
		approvalURL.Path = "/approval"
		qs := approvalURL.Query()
		qs.Set("token", token)
		approvalURL.RawQuery = qs.Encode()
		ghClient := github.NewClient(&http.Client{Transport: tr})
		reqBody := map[string]any{
			"environment_name": deployEnv,
			"comment":          fmt.Sprintf("[approve](%s)", approvalURL),
		}
		logger.Info("send request to GitHub", zap.Int("request.comment.size", len(reqBody["comment"].(string))))
		req, err := ghClient.NewRequest(http.MethodPost, callbackURL, reqBody)
		if err != nil {
			return fmt.Errorf("github.Client.NewRequest: %w", err)
		}
		resp, err := ghClient.Do(ctx, req, nil)
		if err != nil {
			return fmt.Errorf("github.Client.Do: %w", err)
		}
		logger.Info("receive response from GitHub", zap.Int("rate.limit", resp.Rate.Limit), zap.Int("rate.remaining", resp.Rate.Remaining), zap.Time("rate.reset_at", resp.Rate.Reset.Time), zap.Time("token_expiration", resp.TokenExpiration.Time))
	default:
		logger.Info("receive unknown webhook event", zap.String("github.webhook.go_type", fmt.Sprintf("%T", payload)))
	}

	return nil
}

func (h *Handler) handleApproval(ctx context.Context, req events.LambdaFunctionURLRequest) (_ string, err error) {
	ctx, span := h.tracer.Start(ctx, "Handler.handleApproval")
	defer func() {
		code := codes.Ok
		if err != nil {
			code = codes.Error
			span.RecordError(err)
		}
		span.SetStatus(code, "")
		span.End()
	}()

	logger := log.FromContext(ctx)
	raw := req.QueryStringParameters["token"]
	logger = logger.With(zap.String("request_parameter.token", raw))
	defer func() {
		logger.Info("handle /approval")
	}()
	claims, err := h.approvalVerifier.VerifyRequest(ctx, raw)
	if err != nil {
		return "", fmt.Errorf("ApprovalVerifier.VerifyRequest: %w", err)
	}
	logger = logger.With(zap.String("repo", claims.Repo), zap.Int64("run_id", claims.RunID), zap.Int64("installation_id", claims.InstallationID))

	tr, err := ghinstallation.New(otelhttp.NewTransport(nil), h.ghAppID, claims.InstallationID, []byte(h.params.GitHubAppPrivateKey))
	if err != nil {
		return "", fmt.Errorf("ghinstallation.New: %w", err)
	}
	ghClient := github.NewClient(&http.Client{Transport: tr})
	reqBody := map[string]any{
		"environment_name": "production", // TODO
		"state":            "approved",
	}
	ghReq, err := ghClient.NewRequest(http.MethodPost, fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%d/deployment_protection_rule", claims.Repo, claims.RunID), reqBody)
	if err != nil {
		return "", fmt.Errorf("github.Client.NewRequest: %w", err)
	}
	resp, err := ghClient.Do(ctx, ghReq, nil)
	if err != nil {
		return "", fmt.Errorf("github.Client.Do: %w", err)
	}
	logger.Info("receive response from GitHub", zap.Int("rate.limit", resp.Rate.Limit), zap.Int("rate.remaining", resp.Rate.Remaining), zap.Time("rate.reset_at", resp.Rate.Reset.Time), zap.Time("token_expiration", resp.TokenExpiration.Time))

	return fmt.Sprintf("https://github.com/%s/actions/runs/%d", claims.Repo, claims.RunID), nil
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

func ref[T any](v T) *T { return &v }

func NewClaimsFromDeploymentProtectionRuleEvent(payload *github.DeploymentProtectionRuleEvent) (*approvalreq.Claims, error) {
	runID, err := extractRunID(payload.GetDeploymentCallbackURL())
	if err != nil {
		return nil, fmt.Errorf("extractRunID: %w", err)
	}
	claims := &approvalreq.Claims{
		InstallationID: payload.GetInstallation().GetID(),
		Repo:           payload.GetRepo().GetFullName(),
		RunID:          runID,
	}
	return claims, nil
}

func extractRunID(reviewURL string) (int64, error) {
	parsed, err := url.Parse(reviewURL)
	if err != nil {
		return 0, fmt.Errorf("url.Parse: %w", err)
	}
	proceeding, _ := strings.CutSuffix(parsed.Path, "/deployment_protection_rule")
	parts := strings.Split(proceeding, "/")
	runID, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		return 0, err
	}
	return runID, nil
}
