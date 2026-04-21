package dependency

import (
	"context"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
	"github.com/google/go-github/v44/github"
	"github.com/stretchr/testify/mock"
)

func TestUpdateDependencySettingStatusError(t *testing.T) {
	ctx := context.Background()
	mockCode := mocks.CodeServiceClient{}
	mockCode.
		On("PutDependencySetting", mock.Anything, mock.MatchedBy(func(req *code.PutDependencySettingRequest) bool {
			if req == nil || req.DependencySetting == nil {
				return false
			}
			return req.ProjectId == 1 &&
				req.DependencySetting.GithubSettingId == 2 &&
				req.DependencySetting.CodeDataSourceId == 3 &&
				req.DependencySetting.ProjectId == 1 &&
				req.DependencySetting.RepositoryPattern == "owner/*" &&
				req.DependencySetting.Status == code.Status_ERROR &&
				req.DependencySetting.StatusDetail == "scan failed" &&
				req.DependencySetting.ScanAt > 0
		}), mock.Anything).
		Return(&code.PutDependencySettingResponse{DependencySetting: &code.DependencySetting{}}, nil).
		Once()

	s := sqsHandler{
		codeClient: &mockCode,
		logger:     logging.NewLogger(),
	}
	err := s.updateDependencySettingStatusError(ctx, &code.GitHubSetting{
		DependencySetting: &code.DependencySetting{
			ProjectId:         1,
			GithubSettingId:   2,
			CodeDataSourceId:  3,
			RepositoryPattern: "owner/*",
		},
	}, "scan failed")
	if err != nil {
		t.Fatalf("unexpected error: %+v", err)
	}

	mockCode.AssertExpectations(t)
}

func TestHandleRepositoryScan_RequiresRepositoryMetadata(t *testing.T) {
	s := sqsHandler{logger: logging.NewLogger()}
	err := s.handleRepositoryScan(
		context.Background(),
		&message.CodeQueueMessage{ProjectID: 1, GitHubSettingID: 2},
		&code.GitHubSetting{DependencySetting: &code.DependencySetting{}},
		"req-1",
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestScanAllRepositories_UpdatesParentStatusWhenRepositoryFullNameMissing(t *testing.T) {
	ctx := context.Background()
	mockCode := mocks.CodeServiceClient{}
	mockCode.
		On("PutDependencySetting", mock.Anything, mock.MatchedBy(func(req *code.PutDependencySettingRequest) bool {
			if req == nil || req.DependencySetting == nil {
				return false
			}
			return req.ProjectId == 1 &&
				req.DependencySetting.ProjectId == 1 &&
				req.DependencySetting.GithubSettingId == 2 &&
				req.DependencySetting.CodeDataSourceId == 3 &&
				req.DependencySetting.Status == code.Status_ERROR &&
				req.DependencySetting.StatusDetail == "invalid repository metadata: full_name is required" &&
				req.DependencySetting.ScanAt > 0
		}), mock.Anything).
		Return(&code.PutDependencySettingResponse{DependencySetting: &code.DependencySetting{}}, nil).
		Once()

	s := sqsHandler{
		codeClient: &mockCode,
		logger:     logging.NewLogger(),
	}
	msg := &message.CodeQueueMessage{
		ProjectID:       1,
		GitHubSettingID: 2,
	}
	setting := &code.GitHubSetting{
		BaseUrl: "https://github.com/",
		DependencySetting: &code.DependencySetting{
			ProjectId:        1,
			GithubSettingId:  2,
			CodeDataSourceId: 3,
		},
	}
	now := github.Timestamp{Time: time.Unix(1710000000, 0)}
	repo := &github.Repository{
		ID:         github.Int64(10),
		Name:       github.String("repo"),
		Visibility: github.String("private"),
		CloneURL:   github.String("https://github.com/owner/repo.git"),
		CreatedAt:  &now,
		PushedAt:   &now,
		HTMLURL:    github.String("https://github.com/owner/repo"),
	}

	_, err := s.scanAllRepositories(ctx, msg, setting, time.Now(), []*github.Repository{repo})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	mockCode.AssertExpectations(t)
}
