package approvalreq_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/approvalreq"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var signingKey jwk.Key

func TestApprovalVerifier_VerifyRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel = context.WithDeadline(ctx, deadline)
	}
	defer cancel()

	verifier := approvalreq.NewApprovalVerifier(approvalreq.WithSigningKey(signingKey), approvalreq.WithSigningAlgorithm(jwa.HS256))
	type testCase struct {
		name       string
		token      string
		wantClaims *approvalreq.Claims
		wantErr    error
	}
	testCases := []testCase{
		{
			name:  "ok",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnN0YWxsYXRpb25faWQiOjEyMzQsInJlcG8iOiJhZXJlYWwvZG90ZmlsZXMiLCJydW5faWQiOjU2Nzh9.TDsKcPxV0Zo_CpeTwcrF-TiiI3-Y45698rbX2XgqRMI",
			wantClaims: &approvalreq.Claims{
				Repo:           "aereal/dotfiles",
				InstallationID: 1234,
				RunID:          5678,
			},
		},
		{
			name:    "ng/",
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnN0YWxsYXRpb25faWQiOjEyMzQsInJlcG8iOiJhZXJlYWwvZG90ZmlsZXMiLCJydW5faWQiOiIxMjM0In0.Fr6TMUWSgCwhg0p5XJOYwtAVLnTLqV2YmZMHWBX3TN0",
			wantErr: approvalreq.ErrCorruptClaims,
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := verifier.VerifyRequest(ctx, tc.token)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error: got=%v want=%v", err, tc.wantErr)
			}
			if (got != nil) != (tc.wantClaims != nil) {
				t.Fatalf("claims:\n\tgot=%#v\n\twant=%v", got, tc.wantClaims)
			}
			if got == nil {
				return
			}
			if got.InstallationID != tc.wantClaims.InstallationID {
				t.Errorf("Claims.InstallationID:\n\tgot=%d\n\twant=%d", got.InstallationID, tc.wantClaims.InstallationID)
			}
			if got.RunID != tc.wantClaims.RunID {
				t.Errorf("Claims.RunID:\n\tgot=%d\n\twant=%d", got.RunID, tc.wantClaims.RunID)
			}
			if got.Repo != tc.wantClaims.Repo {
				t.Errorf("Claims.Repo:\n\tgot=%q\n\twant=%q", got.Repo, tc.wantClaims.Repo)
			}
		})
	}
}

func TestApprovalVerifier_IssueToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel = context.WithDeadline(ctx, deadline)
	}
	defer cancel()

	type testCase struct {
		name      string
		claims    *approvalreq.Claims
		wantToken string
		wantErr   error
	}
	testCases := []testCase{
		{
			name: "ok",
			claims: &approvalreq.Claims{
				InstallationID: 1234,
				RunID:          5678,
				Repo:           "aereal/dotfiles",
			},
			wantToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpbnN0YWxsYXRpb25faWQiOjEyMzQsInJlcG8iOiJhZXJlYWwvZG90ZmlsZXMiLCJydW5faWQiOjU2Nzh9.TDsKcPxV0Zo_CpeTwcrF-TiiI3-Y45698rbX2XgqRMI",
		},
	}
	verifier := approvalreq.NewApprovalVerifier(approvalreq.WithSigningKey(signingKey), approvalreq.WithSigningAlgorithm(jwa.HS256))
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := verifier.IssueToken(ctx, tc.claims)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error: got=%v want=%v", err, tc.wantErr)
			}
			if tc.wantToken != got {
				t.Fatalf("token:\n\twant=%q\n\tgot=%q", tc.wantToken, got)
			}
		})
	}
}

func init() {
	var err error
	signingKey, err = jwk.FromRaw([]byte("0xdeadbeaf"))
	if err != nil {
		panic(err)
	}
}
