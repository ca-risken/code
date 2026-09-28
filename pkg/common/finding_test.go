package common

import "testing"

func TestGetGitHubOrganization(t *testing.T) {
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
			got := GetGitHubOrganization(tt.repositoryFullName, tt.repositoryName)
			if got != tt.wantTarget {
				t.Errorf("GetGitHubOrganization() = %q, want %q", got, tt.wantTarget)
			}
		})
	}
}
