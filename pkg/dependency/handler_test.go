package dependency

import (
	"context"
	"testing"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
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
