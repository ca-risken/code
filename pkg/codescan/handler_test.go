package codescan

import (
	"context"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
	"github.com/google/go-github/v44/github"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestFinalizeSkippedRepositoryStatus(t *testing.T) {
	tests := []struct {
		name         string
		repo         *github.Repository
		status       code.Status
		statusDetail string
		prepareMock  func(*mocks.CodeServiceClient)
	}{
		{
			name:         "update status to OK",
			repo:         &github.Repository{FullName: github.String("owner/repo")},
			status:       code.Status_OK,
			statusDetail: "Skipped: repository is archived",
			prepareMock: func(mockCode *mocks.CodeServiceClient) {
				mockCode.
					On("PutCodeScanRepository", mock.Anything, mock.MatchedBy(func(req *code.PutCodeScanRepositoryRequest) bool {
						if req == nil || req.CodeScanRepository == nil {
							return false
						}
						return req.ProjectId == 1 &&
							req.CodeScanRepository.GithubSettingId == 2 &&
							req.CodeScanRepository.RepositoryFullName == "owner/repo" &&
							req.CodeScanRepository.Status == code.Status_OK &&
							req.CodeScanRepository.StatusDetail == "Skipped: repository is archived"
					})).
					Return(&emptypb.Empty{}, nil).
					Once()
			},
		},
		{
			name:   "no update for repository without full name",
			repo:   nil,
			status: code.Status_OK,
		},
		{
			name:         "update size limit skip to ERROR",
			repo:         &github.Repository{FullName: github.String("owner/repo")},
			status:       code.Status_ERROR,
			statusDetail: "Skipped: repository size exceeds limit",
			prepareMock: func(mockCode *mocks.CodeServiceClient) {
				mockCode.
					On("PutCodeScanRepository", mock.Anything, mock.MatchedBy(func(req *code.PutCodeScanRepositoryRequest) bool {
						return req.CodeScanRepository.Status == code.Status_ERROR &&
							req.CodeScanRepository.StatusDetail == "Skipped: repository size exceeds limit"
					})).
					Return(&emptypb.Empty{}, nil).
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
			s := sqsHandler{codeClient: &mockCode, logger: logging.NewLogger()}

			s.finalizeSkippedRepositoryStatus(context.Background(), 1, 2, tt.repo, tt.status, tt.statusDetail)

			mockCode.AssertExpectations(t)
		})
	}
}

func TestSkipScan(t *testing.T) {
	now := time.Now()
	type args struct {
		ctx                 context.Context
		repo                *github.Repository
		limitRepositorySize int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Not skip",
			args: args{
				ctx: context.Background(),
				repo: &github.Repository{
					Archived: github.Bool(false),
					Fork:     github.Bool(false),
					Disabled: github.Bool(false),
					Size:     github.Int(3500000),
					PushedAt: &github.Timestamp{Time: now},
				},
				limitRepositorySize: 5000000,
			},
			want: false,
		},
		{
			name: "Skip(repository is nil)",
			args: args{
				ctx:                 context.Background(),
				repo:                nil,
				limitRepositorySize: 5000000,
			},
			want: true,
		},
		{
			name: "Skip(Archived)",
			args: args{
				ctx: context.Background(),
				repo: &github.Repository{
					Archived: github.Bool(true),
					Fork:     github.Bool(false),
					Disabled: github.Bool(false),
					Size:     github.Int(3500000),
					PushedAt: &github.Timestamp{Time: now},
				},
				limitRepositorySize: 5000000,
			},
			want: true,
		},
		{
			name: "Skip(Fork)",
			args: args{
				ctx: context.Background(),
				repo: &github.Repository{
					Archived: github.Bool(false),
					Fork:     github.Bool(true),
					Disabled: github.Bool(false),
					Size:     github.Int(3500000),
					PushedAt: &github.Timestamp{Time: now},
				},
				limitRepositorySize: 5000000,
			},
			want: true,
		},
		{
			name: "Skip(Disabled)",
			args: args{
				ctx: context.Background(),
				repo: &github.Repository{
					Archived: github.Bool(false),
					Fork:     github.Bool(false),
					Disabled: github.Bool(true),
					Size:     github.Int(3500000),
					PushedAt: &github.Timestamp{Time: now},
				},
				limitRepositorySize: 5000000,
			},
			want: true,
		},
		{
			name: "Skip(Empty)",
			args: args{
				ctx: context.Background(),
				repo: &github.Repository{
					Archived: github.Bool(false),
					Fork:     github.Bool(false),
					Disabled: github.Bool(false),
					Size:     github.Int(0),
					PushedAt: &github.Timestamp{Time: now},
				},
				limitRepositorySize: 5000000,
			},
			want: true,
		},
		{
			name: "Skip(Size Limit)",
			args: args{
				ctx: context.Background(),
				repo: &github.Repository{
					Archived: github.Bool(false),
					Fork:     github.Bool(false),
					Disabled: github.Bool(false),
					Size:     github.Int(5000001),
					PushedAt: &github.Timestamp{Time: now},
				},
				limitRepositorySize: 5000000,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := sqsHandler{logger: logging.NewLogger()}
			if got, _, _ := s.skipScan(tt.args.ctx, tt.args.repo, tt.args.limitRepositorySize); got != tt.want {
				t.Errorf("skipScan() = %v, want %v", got, tt.want)
			}
		})
	}
}
