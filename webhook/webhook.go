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

	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/log"
	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/observability"
	"github.com/aereal/paramsenc"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/bradleyfalzon/ghinstallation"
	"github.com/google/go-github/v54/github"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
	issuer            = "github.com/aereal/enjoy-github-custom-deployment-protection-rules"
	grace             = time.Second * 30
	availableDuration = time.Hour * 1

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

	h.params.tokenSigningKey, err = jwk.ParseKey([]byte(h.params.TokenSigningKeyString), jwk.WithPEM(true))
	if err != nil {
		return fmt.Errorf("jwk.ParseKey: %w", err)
	}
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
		var (
			installationID int64
			callbackURL    string
			deployEnv      string
			owner          string
			repoName       string
		)
		fields := []zap.Field{
			zap.Stringp("environment", payload.Environment),
			zap.Stringp("action", payload.Action),
			zap.Stringp("deployment_callback_url", payload.DeploymentCallbackURL),
		}
		if payload.DeploymentCallbackURL != nil {
			callbackURL = *payload.DeploymentCallbackURL
		}
		if inst := payload.Installation; inst != nil {
			if inst.ID != nil {
				installationID = *inst.ID
			}
			fields = append(fields,
				zap.Int64p("installation.target_id", inst.TargetID),
				zap.Stringp("installation.target_type", inst.TargetType),
				zap.Int64p("installation.id", inst.ID))
		}
		if sender := payload.Sender; sender != nil {
			fields = append(fields, zap.Stringp("sender.login", sender.Login))
		}
		if deploy := payload.Deployment; deploy != nil {
			if deploy.Environment != nil {
				deployEnv = *deploy.Environment
			}
			fields = append(fields,
				zap.Stringp("deploy.sha", deploy.SHA),
				zap.Stringp("deploy.ref", deploy.Ref),
				zap.Stringp("deploy.task", deploy.Task),
				zap.Stringp("deploy.environment", deploy.Environment),
				zap.Stringp("deploy.description", deploy.Description),
				zap.Int64p("deploy.id", deploy.ID))
		}
		if repo := payload.Repo; repo != nil {
			if v := repo.Owner; v != nil {
				owner = *v.Login
			}
			if v := repo.Name; v != nil {
				repoName = *v
			}
		}
		logger.Info("receive deployment_protection_rule event", fields...)
		tr, err := ghinstallation.New(otelhttp.NewTransport(nil), h.ghAppID, installationID, []byte(h.params.GitHubAppPrivateKey))
		if err != nil {
			return fmt.Errorf("ghinstallation.New: %w", err)
		}
		runID, err := extractRunID(callbackURL)
		if err != nil {
			return fmt.Errorf("extractRunID: %w", err)
		}
		tok, err := h.buildTransientToken(installationID, fmt.Sprintf("%s/%s", owner, repoName), runID)
		if err != nil {
			return fmt.Errorf("buildTransientToken: %w", err)
		}
		approvalURL, err := url.Parse(h.fnURLOrigin)
		if err != nil {
			return fmt.Errorf("url.Parse: %w", err)
		}
		approvalURL.Path = "/approval"
		qs := approvalURL.Query()
		qs.Set("token", string(tok))
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
	pubKey, err := h.params.tokenSigningKey.PublicKey()
	if err != nil {
		return "", fmt.Errorf("PublicKey: %w", err)
	}
	token, err := jwt.Parse([]byte(raw), jwt.WithKey(jwa.RS256, pubKey))
	if err != nil {
		return "", fmt.Errorf("jwt.Parse: %w", err)
	}
	var (
		repo           string
		runID          int64
		installationID int64
	)
	if v, ok := token.Get("repo"); ok {
		repo, _ = v.(string)
	}
	if v, ok := token.Get("run_id"); ok {
		fv, _ := v.(float64)
		runID = int64(fv)
	}
	if v, ok := token.Get("installation_id"); ok {
		fv, _ := v.(float64)
		installationID = int64(fv)
	}
	logger = logger.With(zap.String("repo", repo), zap.Int64("run_id", runID), zap.Int64("installation_id", installationID))
	if repo == "" || runID == 0 || installationID == 0 {
		return "", errors.New("missing parameter")
	}

	tr, err := ghinstallation.New(otelhttp.NewTransport(nil), h.ghAppID, installationID, []byte(h.params.GitHubAppPrivateKey))
	if err != nil {
		return "", fmt.Errorf("ghinstallation.New: %w", err)
	}
	ghClient := github.NewClient(&http.Client{Transport: tr})
	reqBody := map[string]any{
		"environment_name": "production", // TODO
		"state":            "approved",
	}
	ghReq, err := ghClient.NewRequest(http.MethodPost, fmt.Sprintf("https://api.github.com/repos/%s/actions/runs/%d/deployment_protection_rule", repo, runID), reqBody)
	if err != nil {
		return "", fmt.Errorf("github.Client.NewRequest: %w", err)
	}
	resp, err := ghClient.Do(ctx, ghReq, nil)
	if err != nil {
		return "", fmt.Errorf("github.Client.Do: %w", err)
	}
	logger.Info("receive response from GitHub", zap.Int("rate.limit", resp.Rate.Limit), zap.Int("rate.remaining", resp.Rate.Remaining), zap.Time("rate.reset_at", resp.Rate.Reset.Time), zap.Time("token_expiration", resp.TokenExpiration.Time))

	return fmt.Sprintf("https://github.com/%s/actions/runs/%d", repo, runID), nil
}

func (h *Handler) buildTransientToken(installationID int64, repo string, runID int64) ([]byte, error) {
	tok, err := jwt.NewBuilder().
		Claim("repo", repo).
		Claim("run_id", runID).
		Claim("installation_id", installationID).
		Build()
	if err != nil {
		return nil, fmt.Errorf("jwt.Builder.Build: %w", err)
	}
	serialized, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, h.params.tokenSigningKey))
	if err != nil {
		return nil, fmt.Errorf("jwt.Sign: %w", err)
	}
	return serialized, nil
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

func extractRunID(reviewURL string) (int64, error) {
	parsed, err := url.Parse(reviewURL)
	if err != nil {
		return 0, fmt.Errorf("url.Parse: %w", err)
	}
	proceeding, _ := strings.CutSuffix(parsed.Path, "/deployment_protection_rule")
	parts := strings.Split(proceeding, "/")
	runID, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("strconv.ParseInt: %w", err)
	}
	return runID, nil
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
