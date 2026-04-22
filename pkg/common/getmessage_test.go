package common

import (
	"testing"

	"github.com/ca-risken/datasource-api/pkg/message"
)

func TestGetRepositoriesFromCodeQueueMessage(t *testing.T) {
	tests := []struct {
		name              string
		msg               *message.CodeQueueMessage
		wantLen           int
		wantID            int64
		wantName          string
		wantFullName      string
		wantCloneURL      string
		wantDefaultBranch string
		wantCreatedAtNil  bool
		wantPushedAtNil   bool
	}{
		{
			name: "repository metadata exists",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					ID:            12345,
					Name:          " repo ",
					FullName:      " owner/repo ",
					CloneURL:      " https://github.com/owner/repo.git ",
					DefaultBranch: " main ",
					Visibility:    " private ",
					HTMLURL:       " https://github.com/owner/repo ",
				},
			},
			wantLen:           1,
			wantID:            12345,
			wantName:          "repo",
			wantFullName:      "owner/repo",
			wantCloneURL:      "https://github.com/owner/repo.git",
			wantDefaultBranch: "main",
			wantCreatedAtNil:  true,
			wantPushedAtNil:   true,
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
					Name:          " ",
					FullName:      "owner/repo",
					CloneURL:      "https://github.com/owner/repo.git",
					DefaultBranch: "main",
				},
			},
			wantLen:           1,
			wantName:          "",
			wantFullName:      "owner/repo",
			wantCloneURL:      "https://github.com/owner/repo.git",
			wantDefaultBranch: "main",
			wantCreatedAtNil:  true,
			wantPushedAtNil:   true,
		},
		{
			name: "repository metadata has empty full_name",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					Name:          "repo",
					FullName:      " ",
					CloneURL:      "https://github.com/owner/repo.git",
					DefaultBranch: "main",
				},
			},
			wantLen:           1,
			wantName:          "repo",
			wantFullName:      "",
			wantCloneURL:      "https://github.com/owner/repo.git",
			wantDefaultBranch: "main",
			wantCreatedAtNil:  true,
			wantPushedAtNil:   true,
		},
		{
			name: "repository metadata has empty clone_url",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					Name:          "repo",
					FullName:      "owner/repo",
					CloneURL:      "",
					DefaultBranch: "main",
				},
			},
			wantLen:           1,
			wantName:          "repo",
			wantFullName:      "owner/repo",
			wantCloneURL:      "",
			wantDefaultBranch: "main",
			wantCreatedAtNil:  true,
			wantPushedAtNil:   true,
		},
		{
			name: "repository metadata has empty default_branch",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					Name:          "repo",
					FullName:      "owner/repo",
					CloneURL:      "https://github.com/owner/repo.git",
					DefaultBranch: " ",
				},
			},
			wantLen:           1,
			wantName:          "repo",
			wantFullName:      "owner/repo",
			wantCloneURL:      "https://github.com/owner/repo.git",
			wantDefaultBranch: "",
			wantCreatedAtNil:  true,
			wantPushedAtNil:   true,
		},
		{
			name: "negative timestamps are ignored",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					ID:            12345,
					Name:          "repo",
					FullName:      "owner/repo",
					CloneURL:      "https://github.com/owner/repo.git",
					DefaultBranch: "main",
					CreatedAt:     -1,
					PushedAt:      -1,
				},
			},
			wantLen:           1,
			wantID:            12345,
			wantName:          "repo",
			wantFullName:      "owner/repo",
			wantCloneURL:      "https://github.com/owner/repo.git",
			wantDefaultBranch: "main",
			wantCreatedAtNil:  true,
			wantPushedAtNil:   true,
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
			if got[0].GetDefaultBranch() != tt.wantDefaultBranch {
				t.Errorf("DefaultBranch: got %q want %q", got[0].GetDefaultBranch(), tt.wantDefaultBranch)
			}
			if (got[0].CreatedAt == nil) != tt.wantCreatedAtNil {
				t.Errorf("CreatedAt nil: got %v want %v", got[0].CreatedAt == nil, tt.wantCreatedAtNil)
			}
			if (got[0].PushedAt == nil) != tt.wantPushedAtNil {
				t.Errorf("PushedAt nil: got %v want %v", got[0].PushedAt == nil, tt.wantPushedAtNil)
			}
		})
	}
}
