package common

import (
	"testing"

	"github.com/ca-risken/datasource-api/pkg/message"
)

func TestGetRepositoriesFromCodeQueueMessage(t *testing.T) {
	tests := []struct {
		name         string
		msg          *message.CodeQueueMessage
		wantLen      int
		wantID       int64
		wantName     string
		wantFullName string
		wantCloneURL string
	}{
		{
			name: "repository metadata exists",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					ID:         12345,
					Name:       " repo ",
					FullName:   " owner/repo ",
					CloneURL:   " https://github.com/owner/repo.git ",
					Visibility: " private ",
					HTMLURL:    " https://github.com/owner/repo ",
				},
			},
			wantLen:      1,
			wantID:       12345,
			wantName:     "repo",
			wantFullName: "owner/repo",
			wantCloneURL: "https://github.com/owner/repo.git",
		},
		{
			name:    "repository metadata is nil",
			msg:     &message.CodeQueueMessage{},
			wantLen: 0,
		},
		{
			name: "repository metadata has empty name",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					Name:     " ",
					FullName: "owner/repo",
					CloneURL: "https://github.com/owner/repo.git",
				},
			},
			wantLen: 0,
		},
		{
			name: "repository metadata has empty full_name",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					Name:     "repo",
					FullName: " ",
					CloneURL: "https://github.com/owner/repo.git",
				},
			},
			wantLen: 0,
		},
		{
			name: "repository metadata has empty clone_url",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					Name:     "repo",
					FullName: "owner/repo",
					CloneURL: "",
				},
			},
			wantLen: 0,
		},
		{
			name: "negative timestamps are ignored",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					ID:        12345,
					Name:      "repo",
					FullName:  "owner/repo",
					CloneURL:  "https://github.com/owner/repo.git",
					CreatedAt: -1,
					PushedAt:  -1,
				},
			},
			wantLen:      1,
			wantID:       12345,
			wantName:     "repo",
			wantFullName: "owner/repo",
			wantCloneURL: "https://github.com/owner/repo.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetRepositoriesFromCodeQueueMessage(tt.msg)
			if len(got) != tt.wantLen {
				t.Fatalf("len: got %d want %d", len(got), tt.wantLen)
			}
			if tt.wantLen != 1 {
				return
			}
			if got[0].GetID() != tt.wantID {
				t.Errorf("ID: got %d want %d", got[0].GetID(), tt.wantID)
			}
			if got[0].GetName() != tt.wantName {
				t.Errorf("Name: got %q want %q", got[0].GetName(), tt.wantName)
			}
			if got[0].GetFullName() != tt.wantFullName {
				t.Errorf("FullName: got %q want %q", got[0].GetFullName(), tt.wantFullName)
			}
			if got[0].GetCloneURL() != tt.wantCloneURL {
				t.Errorf("CloneURL: got %q want %q", got[0].GetCloneURL(), tt.wantCloneURL)
			}
			if tt.name == "negative timestamps are ignored" {
				if got[0].CreatedAt != nil {
					t.Errorf("CreatedAt: got non-nil, want nil")
				}
				if got[0].PushedAt != nil {
					t.Errorf("PushedAt: got non-nil, want nil")
				}
			}
		})
	}
}
