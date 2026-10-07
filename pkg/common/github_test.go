package common

import "testing"

func TestGetGitHubOwner(t *testing.T) {
	tests := []struct {
		name       string
		repository string
		want       string
	}{
		{
			name:       "owner from repository full name",
			repository: " owner/repo ",
			want:       "owner",
		},
		{
			name:       "repository name without owner",
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
			got := GetGitHubOwner(tt.repository)
			if got != tt.want {
				t.Errorf("GetGitHubOwner() = %q, want %q", got, tt.want)
			}
		})
	}
}
