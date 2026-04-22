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
	tests := []struct {
		name          string
		gitHubSetting *code.GitHubSetting
		statusDetail  string
		wantErr       bool
		prepareMock   func(*mocks.CodeServiceClient)
	}{
		{
			name: "ok",
			gitHubSetting: &code.GitHubSetting{
				DependencySetting: &code.DependencySetting{
					ProjectId:         1,
					GithubSettingId:   2,
					CodeDataSourceId:  3,
					RepositoryPattern: "owner/*",
				},
			},
			statusDetail: "scan failed",
			prepareMock: func(mockCode *mocks.CodeServiceClient) {
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
			},
		},
		{
			name:          "ng nil dependency setting",
			gitHubSetting: &code.GitHubSetting{},
			statusDetail:  "scan failed",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockCode := mocks.CodeServiceClient{}
			if tt.prepareMock != nil {
				tt.prepareMock(&mockCode)
			}

			s := sqsHandler{
				codeClient: &mockCode,
				logger:     logging.NewLogger(),
			}
			err := s.updateDependencySettingStatusError(ctx, tt.gitHubSetting, tt.statusDetail)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}

			mockCode.AssertExpectations(t)
		})
	}
}

func TestHandleRepositoryScan(t *testing.T) {
	tests := []struct {
		name        string
		msg         *message.CodeQueueMessage
		wantErr     bool
		prepareMock func(*mocks.CodeServiceClient)
	}{
		{
			name:    "ng missing repository metadata",
			msg:     &message.CodeQueueMessage{ProjectID: 1, GitHubSettingID: 2},
			wantErr: true,
			prepareMock: func(mockCode *mocks.CodeServiceClient) {
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
							req.DependencySetting.StatusDetail == "repository metadata is required in queue message" &&
							req.DependencySetting.ScanAt > 0
					}), mock.Anything).
					Return(&code.PutDependencySettingResponse{DependencySetting: &code.DependencySetting{}}, nil).
					Once()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCode := mocks.CodeServiceClient{}
			if tt.prepareMock != nil {
				tt.prepareMock(&mockCode)
			}
			s := sqsHandler{
				codeClient: &mockCode,
				logger:     logging.NewLogger(),
			}
			err := s.handleRepositoryScan(
				context.Background(),
				tt.msg,
				&code.GitHubSetting{DependencySetting: &code.DependencySetting{
					ProjectId:        1,
					GithubSettingId:  2,
					CodeDataSourceId: 3,
				}},
				"req-1",
			)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}
			mockCode.AssertExpectations(t)
		})
	}
}

func TestScanAllRepositories(t *testing.T) {
	now := github.Timestamp{Time: time.Unix(1710000000, 0)}
	tests := []struct {
		name        string
		repos       []*github.Repository
		wantErr     bool
		prepareMock func(*mocks.CodeServiceClient)
	}{
		{
			name: "ng full name missing updates parent status",
			repos: []*github.Repository{
				{
					ID:         github.Int64(10),
					Name:       github.String("repo"),
					Visibility: github.String("private"),
					CloneURL:   github.String("https://github.com/owner/repo.git"),
					CreatedAt:  &now,
					PushedAt:   &now,
					HTMLURL:    github.String("https://github.com/owner/repo"),
				},
			},
			wantErr: true,
			prepareMock: func(mockCode *mocks.CodeServiceClient) {
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
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockCode := mocks.CodeServiceClient{}
			if tt.prepareMock != nil {
				tt.prepareMock(&mockCode)
			}

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

			_, err := s.scanAllRepositories(ctx, msg, setting, time.Now(), tt.repos)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}

			mockCode.AssertExpectations(t)
		})
	}
}
