package dependency

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
	"github.com/google/go-github/v44/github"
	"github.com/stretchr/testify/mock"
)

func TestValidateRepositoryForDependency(t *testing.T) {
	baseURL := "https://api.github.com/"

	tests := []struct {
		name    string
		repo    *github.Repository
		wantErr string
	}{
		{
			name: "valid repository",
			repo: &github.Repository{
				ID:       github.Int64(1),
				Name:     github.String("repo"),
				FullName: github.String("owner/repo"),
				CloneURL: github.String("https://github.com/owner/repo.git"),
			},
		},
		{
			name: "missing repository id",
			repo: &github.Repository{
				Name:     github.String("repo"),
				FullName: github.String("owner/repo"),
				CloneURL: github.String("https://github.com/owner/repo.git"),
			},
			wantErr: "repository id must be > 0",
		},
		{
			name: "negative repository id",
			repo: &github.Repository{
				ID:       github.Int64(-1),
				Name:     github.String("repo"),
				FullName: github.String("owner/repo"),
				CloneURL: github.String("https://github.com/owner/repo.git"),
			},
			wantErr: "repository id must be > 0",
		},
		{
			name: "basic validation still applies",
			repo: &github.Repository{
				ID:       github.Int64(1),
				Name:     github.String("repo"),
				FullName: github.String("owner/repo"),
				CloneURL: github.String("http://github.com/owner/repo.git"),
			},
			wantErr: "clone_url scheme must be https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRepositoryForDependency(tt.repo, baseURL)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("validateRepositoryForDependency() unexpected error = %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("validateRepositoryForDependency() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateRepositoryForDependency() error = %v, want substring %q", err, tt.wantErr)
				}
			}
		})
	}
}

func TestScanAllRepositories_SkipsValidationFailureWithoutUpdatingErrorStatus(t *testing.T) {
	ctx := context.Background()
	mockCode := mocks.CodeServiceClient{}
	s := sqsHandler{
		codeClient: &mockCode,
		logger:     logging.NewLogger(),
	}

	msg := &message.CodeQueueMessage{
		ProjectID:       1,
		GitHubSettingID: 2,
	}
	setting := &code.GitHubSetting{
		BaseUrl: "",
	}
	repos := []*github.Repository{
		{
			Name:     github.String("repo"),
			FullName: github.String("owner/repo"),
		},
	}

	got, err := s.scanAllRepositories(ctx, msg, setting, time.Now(), repos)
	if err != nil {
		t.Fatalf("unexpected error: %+v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected scanned repositories: %+v", got)
	}

	mockCode.AssertNotCalled(t, "PutDependencyRepository", mock.Anything, mock.Anything)
}
