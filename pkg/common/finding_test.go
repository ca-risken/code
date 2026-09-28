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
			name:               "repository full name",
			repositoryFullName: " owner/repo ",
			repositoryName:     "legacy-repo",
			wantTarget:         "owner/repo",
		},
		{
			name:           "legacy repository name",
			repositoryName: " legacy-repo ",
			wantTarget:     "legacy-repo",
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
