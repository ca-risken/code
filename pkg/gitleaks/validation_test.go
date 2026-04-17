package gitleaks

import (
	"context"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
	"github.com/google/go-github/v44/github"
	"github.com/stretchr/testify/mock"
)

func TestValidateRepository(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		repo    *github.Repository
		baseURL string
		wantErr bool
	}{
		{
			name: "valid repository",
			repo: &github.Repository{
				ID:         github.Int64(1),
				Name:       github.String("repo"),
				FullName:   github.String("owner/repo"),
				CloneURL:   github.String("https://github.com/owner/repo.git"),
				Visibility: github.String("private"),
				HTMLURL:    github.String("https://github.com/owner/repo"),
				CreatedAt: &github.Timestamp{
					Time: now.Add(-1 * time.Hour),
				},
				PushedAt: &github.Timestamp{
					Time: now,
				},
			},
			baseURL: "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRepositoryForGitleaks(tt.repo, tt.baseURL)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}
}

func TestValidateRepository_CloneURLValidation(t *testing.T) {
	baseRepo := &github.Repository{
		ID:         github.Int64(1),
		Name:       github.String("repo"),
		FullName:   github.String("owner/repo"),
		CloneURL:   github.String("https://github.com/owner/repo.git"),
		Visibility: github.String("private"),
		HTMLURL:    github.String("https://github.com/owner/repo"),
		CreatedAt:  &github.Timestamp{Time: time.Now().Add(-1 * time.Hour)},
		PushedAt:   &github.Timestamp{Time: time.Now()},
	}
	tests := []struct {
		name    string
		repo    *github.Repository
		baseURL string
		wantErr bool
	}{
		{
			name:    "invalid scheme",
			repo:    func() *github.Repository { r := *baseRepo; r.CloneURL = github.String("file:///tmp/repo"); return &r }(),
			baseURL: "",
			wantErr: true,
		},
		{
			name: "host mismatch",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CloneURL = github.String("https://evil.example.com/owner/repo.git")
				return &r
			}(),
			baseURL: "https://api.github.com/",
			wantErr: true,
		},
		{
			name: "path mismatch",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CloneURL = github.String("https://github.com/owner/other.git")
				return &r
			}(),
			baseURL: "",
			wantErr: true,
		},
		{
			name: "enterprise host accepted",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CloneURL = github.String("https://github.example.com/owner/repo.git")
				r.HTMLURL = github.String("https://github.example.com/owner/repo")
				return &r
			}(),
			baseURL: "https://github.example.com/api/v3/",
			wantErr: false,
		},
		{
			name: "enterprise mode rejects github.com clone_url",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CloneURL = github.String("https://github.com/owner/repo.git")
				return &r
			}(),
			baseURL: "https://github.example.com/api/v3/",
			wantErr: true,
		},
		{
			name: "html_url invalid scheme",
			repo: func() *github.Repository {
				r := *baseRepo
				r.HTMLURL = github.String("http://github.com/owner/repo")
				return &r
			}(),
			baseURL: "",
			wantErr: true,
		},
		{
			name: "html_url host mismatch",
			repo: func() *github.Repository {
				r := *baseRepo
				r.HTMLURL = github.String("https://evil.example.com/owner/repo")
				return &r
			}(),
			baseURL: "https://api.github.com/",
			wantErr: true,
		},
		{
			name: "html_url path mismatch",
			repo: func() *github.Repository {
				r := *baseRepo
				r.HTMLURL = github.String("https://github.com/owner/other")
				return &r
			}(),
			baseURL: "",
			wantErr: true,
		},
		{
			name:    "invalid github base url configuration",
			repo:    baseRepo,
			baseURL: "://invalid-base-url",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRepositoryForGitleaks(tt.repo, tt.baseURL)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}
}

func TestValidateRepository_TimestampValidation(t *testing.T) {
	baseRepo := &github.Repository{
		ID:         github.Int64(1),
		Name:       github.String("repo"),
		FullName:   github.String("owner/repo"),
		CloneURL:   github.String("https://github.com/owner/repo.git"),
		Visibility: github.String("private"),
		HTMLURL:    github.String("https://github.com/owner/repo"),
		CreatedAt:  &github.Timestamp{Time: time.Now().Add(-1 * time.Hour)},
		PushedAt:   &github.Timestamp{Time: time.Now()},
	}
	tests := []struct {
		name    string
		repo    *github.Repository
		wantErr bool
	}{
		{
			name: "created_at negative unix",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CreatedAt = &github.Timestamp{Time: time.Unix(-1, 0)}
				return &r
			}(),
			wantErr: true,
		},
		{
			name: "pushed_at zero unix",
			repo: func() *github.Repository {
				r := *baseRepo
				r.PushedAt = &github.Timestamp{Time: time.Unix(0, 0)}
				return &r
			}(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRepositoryForGitleaks(tt.repo, "")
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}
}

func TestScanDiffRepositories_DoesNotUpdateErrorStatusOnValidationFailure(t *testing.T) {
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
	repos := []*github.Repository{
		{
			Name:     github.String("repo"),
			FullName: github.String("owner/repo"),
		},
	}

	err := s.scanDiffRepositories(ctx, msg, "token", repos, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	mockCode.AssertNotCalled(t, "PutGitleaksRepository", mock.Anything, mock.Anything)
}
