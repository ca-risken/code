package common

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v44/github"
)

func TestValidateRepository(t *testing.T) {
	baseURL := "https://api.github.com/"
	now := time.Unix(1700000000, 0)

	validRepo := &github.Repository{
		ID:         github.Int64(1),
		Name:       github.String("repo"),
		FullName:   github.String("owner/repo"),
		Visibility: github.String("private"),
		CloneURL:   github.String("https://github.com/owner/repo.git"),
		CreatedAt:  &github.Timestamp{Time: now},
		PushedAt:   &github.Timestamp{Time: now},
		HTMLURL:    github.String("https://github.com/owner/repo"),
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
			name: "missing repository id",
			repo: &github.Repository{
				Name:       github.String("repo"),
				FullName:   github.String("owner/repo"),
				Visibility: github.String("private"),
				CloneURL:   github.String("https://github.com/owner/repo.git"),
				CreatedAt:  &github.Timestamp{Time: now},
				PushedAt:   &github.Timestamp{Time: now},
				HTMLURL:    github.String("https://github.com/owner/repo"),
			},
			wantErr: "repository id must be > 0",
		},
		{
			name: "negative repository id",
			repo: &github.Repository{
				ID:         github.Int64(-1),
				Name:       github.String("repo"),
				FullName:   github.String("owner/repo"),
				Visibility: github.String("private"),
				CloneURL:   github.String("https://github.com/owner/repo.git"),
				CreatedAt:  &github.Timestamp{Time: now},
				PushedAt:   &github.Timestamp{Time: now},
				HTMLURL:    github.String("https://github.com/owner/repo"),
			},
			wantErr: "repository id must be > 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRepository(tt.repo, baseURL)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("ValidateRepository() unexpected error = %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ValidateRepository() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ValidateRepository() error = %v, want substring %q", err, tt.wantErr)
				}
			}
		})
	}
}
