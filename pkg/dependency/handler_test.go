package dependency

import (
	"context"
	"testing"

	"github.com/ca-risken/code/pkg/common"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGetRepositoriesFromCodeQueueMessage(t *testing.T) {
	tests := []struct {
		name    string
		msg     *message.CodeQueueMessage
		wantLen int
		want    *wantRepository // nil when wantLen != 1
	}{
		{
			name: "repository metadata exists",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					ID:         12345,
					Name:       "repo",
					FullName:   "owner/repo",
					CloneURL:   "https://github.com/owner/repo.git",
					Visibility: "private",
					Archived:   false,
					Fork:       false,
					Disabled:   false,
					Size:       123,
					HTMLURL:    "https://github.com/owner/repo",
				},
			},
			wantLen: 1,
			want: &wantRepository{
				fullName: "owner/repo",
				cloneURL: "https://github.com/owner/repo.git",
				id:       12345,
			},
		},
		{
			name: "repository metadata is trimmed before building repository",
			msg: &message.CodeQueueMessage{
				Repository: &message.RepositoryMetadata{
					ID:         12345,
					Name:       " repo ",
					FullName:   " owner/repo ",
					CloneURL:   " https://github.com/owner/repo.git ",
					Visibility: " private ",
					Archived:   false,
					Fork:       false,
					Disabled:   false,
					Size:       123,
					HTMLURL:    " https://github.com/owner/repo ",
				},
			},
			wantLen: 1,
			want: &wantRepository{
				fullName: "owner/repo",
				cloneURL: "https://github.com/owner/repo.git",
				id:       12345,
			},
		},
		{
			name:    "repository metadata is nil",
			msg:     &message.CodeQueueMessage{},
			wantLen: 0,
			want:    nil,
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
			wantLen: 1,
			want: &wantRepository{
				fullName: "",
				cloneURL: "https://github.com/owner/repo.git",
				id:       0,
			},
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
			wantLen: 1,
			want: &wantRepository{
				fullName: "owner/repo",
				cloneURL: "https://github.com/owner/repo.git",
				id:       0,
			},
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
			wantLen: 1,
			want: &wantRepository{
				fullName: "owner/repo",
				cloneURL: "",
				id:       0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.GetRepositoriesFromCodeQueueMessage(tt.msg)
			if len(got) != tt.wantLen {
				t.Fatalf("len: got %d want %d", len(got), tt.wantLen)
			}
			if tt.wantLen != 1 {
				return
			}
			if tt.want == nil {
				t.Fatal("want must be set when wantLen == 1")
			}
			if got[0].GetFullName() != tt.want.fullName {
				t.Errorf("FullName: got %q want %q", got[0].GetFullName(), tt.want.fullName)
			}
			if got[0].GetCloneURL() != tt.want.cloneURL {
				t.Errorf("CloneURL: got %q want %q", got[0].GetCloneURL(), tt.want.cloneURL)
			}
			if got[0].GetID() != tt.want.id {
				t.Errorf("ID: got %d want %d", got[0].GetID(), tt.want.id)
			}
		})
	}
}

type wantRepository struct {
	fullName string
	cloneURL string
	id       int64
}

func TestHandleRepositoryScan_UpdatesStatusWhenRepositoryNameExists(t *testing.T) {
	ctx := context.Background()
	mockCode := mocks.CodeServiceClient{}
	mockCode.
		On("PutDependencyRepository", mock.Anything, mock.MatchedBy(func(req *code.PutDependencyRepositoryRequest) bool {
			if req == nil || req.DependencyRepository == nil {
				return false
			}
			return req.ProjectId == 1 &&
				req.DependencyRepository.GithubSettingId == 2 &&
				req.DependencyRepository.RepositoryFullName == "owner/repo" &&
				req.DependencyRepository.Status == code.Status_ERROR
		}), mock.Anything).
		Return(&emptypb.Empty{}, nil).
		Once()

	s := sqsHandler{
		codeClient: &mockCode,
		logger:     logging.NewLogger(),
	}
	msg := &message.CodeQueueMessage{
		ProjectID:       1,
		GitHubSettingID: 2,
		RepositoryName:  "owner/repo",
	}
	setting := &code.GitHubSetting{
		DependencySetting: &code.DependencySetting{},
	}

	err := s.handleRepositoryScan(ctx, msg, setting, "req-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	mockCode.AssertExpectations(t)
}
