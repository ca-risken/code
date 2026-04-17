package common

import (
	"strings"
	"testing"

	"github.com/google/go-github/v44/github"
)

func TestValidateRepositoryBasic(t *testing.T) {
	baseURL := "https://api.github.com/"

	validRepo := &github.Repository{
		Name:     github.String("repo"),
		FullName: github.String("owner/repo"),
		CloneURL: github.String("https://github.com/owner/repo.git"),
	}

	tests := []struct {
		name    string
		repo    *github.Repository
		wantErr string
	}{
		{
			name: "valid repository",
			repo: validRepo,
		},
		{
			name: "missing html url is allowed in basic validation",
			repo: &github.Repository{
				Name:     github.String("repo"),
				FullName: github.String("owner/repo"),
				CloneURL: github.String("https://github.com/owner/repo.git"),
			},
		},
		{
			name: "missing timestamps are allowed in basic validation",
			repo: &github.Repository{
				Name:     github.String("repo"),
				FullName: github.String("owner/repo"),
				CloneURL: github.String("https://github.com/owner/repo.git"),
			},
		},
		{
			name: "repository name contains path separator",
			repo: &github.Repository{
				Name:     github.String("../../repo"),
				FullName: github.String("owner/repo"),
				CloneURL: github.String("https://github.com/owner/repo.git"),
			},
			wantErr: "name must not contain path separators or traversal segments",
		},
		{
			name: "repository name does not match full name",
			repo: &github.Repository{
				Name:     github.String("other"),
				FullName: github.String("owner/repo"),
				CloneURL: github.String("https://github.com/owner/repo.git"),
			},
			wantErr: "name does not match repository full_name",
		},
		{
			name: "missing clone url",
			repo: &github.Repository{
				Name:     github.String("repo"),
				FullName: github.String("owner/repo"),
			},
			wantErr: "clone_url is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRepositoryBasic(tt.repo, baseURL)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("ValidateRepositoryBasic() unexpected error = %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ValidateRepositoryBasic() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ValidateRepositoryBasic() error = %v, want substring %q", err, tt.wantErr)
				}
			}
		})
	}
}
