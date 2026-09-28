package common

import (
	"testing"

	"github.com/ca-risken/core/proto/finding"
)

func TestSetGitHubProvider(t *testing.T) {
	tests := []struct {
		name               string
		repositoryFullName string
		repositoryName     string
		wantTarget         string
	}{
		{
			name:               "organization from repository full name",
			repositoryFullName: " owner/repo ",
			repositoryName:     "legacy-repo",
			wantTarget:         "owner",
		},
		{
			name:           "organization from legacy repository name",
			repositoryName: " legacy-owner/legacy-repo ",
			wantTarget:     "legacy-owner",
		},
		{
			name:           "repository name without organization",
			repositoryName: "legacy-repo",
			wantTarget:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &finding.FindingForUpsert{}

			SetGitHubProvider(f, tt.repositoryFullName, tt.repositoryName)

			if f.Provider != ProviderGitHub {
				t.Errorf("Provider = %q, want %q", f.Provider, ProviderGitHub)
			}
			if f.ProviderTarget != tt.wantTarget {
				t.Errorf("ProviderTarget = %q, want %q", f.ProviderTarget, tt.wantTarget)
			}
		})
	}
}
