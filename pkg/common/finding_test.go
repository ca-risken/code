package common

import "testing"

func TestGetGitHubOrganization(t *testing.T) {
	tests := []struct {
		name       string
		repository string
		want       string
	}{
		{
			name:       "organization from repository full name",
			repository: " owner/repo ",
			want:       "owner",
		},
		{
			name:       "repository name without organization",
			repository: "repo",
			want:       "",
		},
		{
			name: "empty repository",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetGitHubOrganization(tt.repository)
			if got != tt.want {
				t.Errorf("GetGitHubOrganization() = %q, want %q", got, tt.want)
			}
		})
	}
}
