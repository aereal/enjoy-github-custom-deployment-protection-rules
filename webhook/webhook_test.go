package webhook_test

import (
	"errors"
	"testing"

	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/approvalreq"
	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/webhook"
	"github.com/google/go-github/v54/github"
)

func TestNewClaimsFromDeploymentProtectionRuleEvent(t *testing.T) {
	type testCase struct {
		name       string
		payload    *github.DeploymentProtectionRuleEvent
		wantClaims *approvalreq.Claims
		wantErr    error
	}
	testCases := []testCase{
		{
			name: "ok",
			payload: &github.DeploymentProtectionRuleEvent{
				Repo: &github.Repository{
					FullName: ref("aereal/dotfiles"),
				},
				Installation: &github.Installation{
					ID: ref(int64(5678)),
				},
				DeploymentCallbackURL: ref("https://api.github.com/repos/aereal/dotfiles/actions/runs/1234/deployment_protection_rule"),
			},
			wantClaims: &approvalreq.Claims{
				RunID:          1234,
				InstallationID: 5678,
				Repo:           "aereal/dotfiles",
			},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := webhook.NewClaimsFromDeploymentProtectionRuleEvent(tc.payload)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error:\n\twant=%v\n\tgot=%v", tc.wantErr, err)
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

func ref[T any](v T) *T { return &v }
