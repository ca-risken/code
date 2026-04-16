package dependency

import (
	"testing"
	"time"

	"github.com/ca-risken/code/pkg/common"
	"github.com/google/go-github/v44/github"
)

func TestValidateRepository_CloneURLValidation(t *testing.T) {
	baseRepo := &github.Repository{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := common.ValidateRepository(tt.repo, tt.baseURL)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}
}
