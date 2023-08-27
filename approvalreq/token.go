package approvalreq

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName = "github.com/aereal/enjoy-github-custom-deployment-protection-rules/approvalreq.ApprovalVerifier"
)

var (
	ErrSigningKeyRequired = errors.New("signing key is required")
	ErrCorruptClaims      = errors.New("claims does not have enough fields")
)

type NewApprovalVerifierOption func(*ApprovalVerifier)

func WithSigningKey(signingKey jwk.Key) NewApprovalVerifierOption {
	return func(av *ApprovalVerifier) { av.signingKey = signingKey }
}

func WithSigningAlgorithm(alg jwa.SignatureAlgorithm) NewApprovalVerifierOption {
	return func(av *ApprovalVerifier) { av.signingAlg = alg }
}

type ApprovalVerifier struct {
	tracer     trace.Tracer
	signingKey jwk.Key
	signingAlg jwa.SignatureAlgorithm
}

func NewApprovalVerifier(opts ...NewApprovalVerifierOption) *ApprovalVerifier {
	av := &ApprovalVerifier{
		tracer:     otel.GetTracerProvider().Tracer(tracerName),
		signingAlg: jwa.RS256,
	}
	for _, o := range opts {
		o(av)
	}
	return av
}

type Claims struct {
	InstallationID int64
	Repo           string
	RunID          int64
}

func (c *Claims) validate() error {
	if c.InstallationID == 0 || c.RunID == 0 || c.Repo == "" {
		return ErrCorruptClaims
	}
	return nil
}

func (c *Claims) asToken() (jwt.Token, error) {
	return jwt.NewBuilder().
		Claim("repo", c.Repo).
		Claim("run_id", c.RunID).
		Claim("installation_id", c.InstallationID).
		Build()
}

func (av *ApprovalVerifier) IssueToken(ctx context.Context, claims *Claims) (_ string, err error) {
	_, span := av.tracer.Start(ctx, "ApprovalVerifier.IssueToken")
	defer func() {
		code := codes.Ok
		if err != nil {
			span.RecordError(err)
			code = codes.Error
		}
		span.SetStatus(code, "")
		span.End()
	}()

	if av.signingKey == nil {
		return "", ErrSigningKeyRequired
	}

	tok, err := claims.asToken()
	if err != nil {
		return "", fmt.Errorf("jwt.Builder.Build: %w", err)
	}
	serialized, err := jwt.Sign(tok, jwt.WithKey(av.signingAlg, av.signingKey))
	if err != nil {
		return "", fmt.Errorf("jwt.Sign: %w", err)
	}
	return string(serialized), nil
}

func (av *ApprovalVerifier) VerifyRequest(ctx context.Context, token string) (_ *Claims, err error) {
	_, span := av.tracer.Start(ctx, "ApprovalVerifier.VerifyRequest")
	defer func() {
		code := codes.Ok
		if err != nil {
			span.RecordError(err)
			code = codes.Error
		}
		span.SetStatus(code, "")
		span.End()
	}()

	pubKey, err := av.signingKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("jwk.Key.PublicKey: %w", err)
	}
	parsed, err := jwt.Parse([]byte(token), jwt.WithKey(av.signingAlg, pubKey))
	if err != nil {
		return nil, fmt.Errorf("jwt.Parse: %w", err)
	}
	claims := &Claims{}
	private := parsed.PrivateClaims()
	if v, ok := private["repo"].(string); ok {
		claims.Repo = v
	}
	if v, ok := private["installation_id"].(float64); ok {
		claims.InstallationID = int64(v)
	}
	if v, ok := private["run_id"].(float64); ok {
		claims.RunID = int64(v)
	}
	if err := claims.validate(); err != nil {
		return nil, err
	}

	return claims, nil
}
