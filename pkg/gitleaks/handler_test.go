package gitleaks

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ca-risken/code/pkg/common"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
	"github.com/google/go-github/v44/github"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGetRepositoriesFromCodeQueueMessage(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name         string
		msg          *message.CodeQueueMessage
		wantCount    int
		wantID       int64
		wantFullName string
		wantCloneURL string
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
					CreatedAt:  now - 3600,
					PushedAt:   now,
					HTMLURL:    "https://github.com/owner/repo",
				},
			},
			wantCount:    1,
			wantID:       12345,
			wantFullName: "owner/repo",
			wantCloneURL: "https://github.com/owner/repo.git",
		},
		{
			name:      "repository metadata is nil",
			msg:       &message.CodeQueueMessage{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repos := common.GetRepositoriesFromCodeQueueMessage(tt.msg)
			if len(repos) != tt.wantCount {
				t.Fatalf("unexpected repository count: got=%d want=%d", len(repos), tt.wantCount)
			}
			if tt.wantCount == 0 {
				return
			}
			if repos[0].GetID() != tt.wantID {
				t.Fatalf("unexpected id: got=%d want=%d", repos[0].GetID(), tt.wantID)
			}
			if repos[0].GetFullName() != tt.wantFullName {
				t.Fatalf("unexpected full_name: got=%q want=%q", repos[0].GetFullName(), tt.wantFullName)
			}
			if repos[0].GetCloneURL() != tt.wantCloneURL {
				t.Fatalf("unexpected clone_url: got=%q want=%q", repos[0].GetCloneURL(), tt.wantCloneURL)
			}
		})
	}
}

func TestValidateRepository(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		repo    *github.Repository
		baseURL string
		wantErr bool
	}{
		{
			name: "valid repository",
			repo: &github.Repository{
				ID:         github.Int64(1),
				Name:       github.String("repo"),
				FullName:   github.String("owner/repo"),
				CloneURL:   github.String("https://github.com/owner/repo.git"),
				Visibility: github.String("private"),
				HTMLURL:    github.String("https://github.com/owner/repo"),
				CreatedAt: &github.Timestamp{
					Time: now.Add(-1 * time.Hour),
				},
				PushedAt: &github.Timestamp{
					Time: now,
				},
			},
			baseURL: "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := common.ValidateRepository(tt.repo, tt.baseURL)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}
}

func TestValidateRepository_CloneURLValidation(t *testing.T) {
	baseRepo := &github.Repository{
		ID:         github.Int64(1),
		Name:       github.String("repo"),
		FullName:   github.String("owner/repo"),
		CloneURL:   github.String("https://github.com/owner/repo.git"),
		Visibility: github.String("private"),
		HTMLURL:    github.String("https://github.com/owner/repo"),
		CreatedAt:  &github.Timestamp{Time: time.Now().Add(-1 * time.Hour)},
		PushedAt:   &github.Timestamp{Time: time.Now()},
	}
	tests := []struct {
		name    string
		repo    *github.Repository
		baseURL string
		wantErr bool
	}{
		{
			name:    "invalid scheme",
			repo:    func() *github.Repository { r := *baseRepo; r.CloneURL = github.String("file:///tmp/repo"); return &r }(),
			baseURL: "",
			wantErr: true,
		},
		{
			name: "host mismatch",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CloneURL = github.String("https://evil.example.com/owner/repo.git")
				return &r
			}(),
			baseURL: "https://api.github.com/",
			wantErr: true,
		},
		{
			name: "path mismatch",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CloneURL = github.String("https://github.com/owner/other.git")
				return &r
			}(),
			baseURL: "",
			wantErr: true,
		},
		{
			name: "enterprise host accepted",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CloneURL = github.String("https://github.example.com/owner/repo.git")
				r.HTMLURL = github.String("https://github.example.com/owner/repo")
				return &r
			}(),
			baseURL: "https://github.example.com/api/v3/",
			wantErr: false,
		},
		{
			name: "enterprise mode rejects github.com clone_url",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CloneURL = github.String("https://github.com/owner/repo.git")
				return &r
			}(),
			baseURL: "https://github.example.com/api/v3/",
			wantErr: true,
		},
		{
			name: "html_url invalid scheme",
			repo: func() *github.Repository {
				r := *baseRepo
				r.HTMLURL = github.String("http://github.com/owner/repo")
				return &r
			}(),
			baseURL: "",
			wantErr: true,
		},
		{
			name: "html_url host mismatch",
			repo: func() *github.Repository {
				r := *baseRepo
				r.HTMLURL = github.String("https://evil.example.com/owner/repo")
				return &r
			}(),
			baseURL: "https://api.github.com/",
			wantErr: true,
		},
		{
			name: "html_url path mismatch",
			repo: func() *github.Repository {
				r := *baseRepo
				r.HTMLURL = github.String("https://github.com/owner/other")
				return &r
			}(),
			baseURL: "",
			wantErr: true,
		},
		{
			name:    "invalid github base url configuration",
			repo:    baseRepo,
			baseURL: "://invalid-base-url",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := common.ValidateRepository(tt.repo, tt.baseURL)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}
}

func TestValidateRepository_TimestampValidation(t *testing.T) {
	baseRepo := &github.Repository{
		ID:         github.Int64(1),
		Name:       github.String("repo"),
		FullName:   github.String("owner/repo"),
		CloneURL:   github.String("https://github.com/owner/repo.git"),
		Visibility: github.String("private"),
		HTMLURL:    github.String("https://github.com/owner/repo"),
		CreatedAt:  &github.Timestamp{Time: time.Now().Add(-1 * time.Hour)},
		PushedAt:   &github.Timestamp{Time: time.Now()},
	}
	tests := []struct {
		name    string
		repo    *github.Repository
		wantErr bool
	}{
		{
			name: "created_at negative unix",
			repo: func() *github.Repository {
				r := *baseRepo
				r.CreatedAt = &github.Timestamp{Time: time.Unix(-1, 0)}
				return &r
			}(),
			wantErr: true,
		},
		{
			name: "pushed_at zero unix",
			repo: func() *github.Repository {
				r := *baseRepo
				r.PushedAt = &github.Timestamp{Time: time.Unix(0, 0)}
				return &r
			}(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := common.ValidateRepository(tt.repo, "")
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}
}

func TestSkipScan(t *testing.T) {
	now := time.Now()
	type args struct {
		ctx                 context.Context
		repo                *github.Repository
		lastScannedAt       *time.Time
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
				lastScannedAt:       func() *time.Time { l := now.Add(-1 * time.Hour); return &l }(),
				limitRepositorySize: 5000000,
			},
			want: false,
		},
		{
			name: "Skip(repository is nil)",
			args: args{
				ctx:                 context.Background(),
				repo:                nil,
				lastScannedAt:       func() *time.Time { l := now.Add(-1 * time.Hour); return &l }(),
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
				lastScannedAt:       func() *time.Time { l := now.Add(-1 * time.Hour); return &l }(),
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
				lastScannedAt:       func() *time.Time { l := now.Add(-1 * time.Hour); return &l }(),
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
				lastScannedAt:       func() *time.Time { l := now.Add(-1 * time.Hour); return &l }(),
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
				lastScannedAt:       func() *time.Time { l := now.Add(-1 * time.Hour); return &l }(),
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
				lastScannedAt:       func() *time.Time { l := now.Add(-1 * time.Hour); return &l }(),
				limitRepositorySize: 5000000,
			},
			want: true,
		},
		{
			name: "Skip(already scanned)",
			args: args{
				ctx: context.Background(),
				repo: &github.Repository{
					Archived: github.Bool(false),
					Fork:     github.Bool(false),
					Disabled: github.Bool(false),
					Size:     github.Int(3500000),
					PushedAt: &github.Timestamp{Time: now},
				},
				lastScannedAt:       func() *time.Time { l := now.Add(1 * time.Hour); return &l }(),
				limitRepositorySize: 5000000,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := sqsHandler{logger: logging.NewLogger()}
			if got, _, _ := s.skipScan(tt.args.ctx, tt.args.repo, tt.args.lastScannedAt, tt.args.limitRepositorySize); got != tt.want {
				t.Errorf("skipScan() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
			statusDetail: "Skipped: repository was already scanned",
			prepareMock: func(mockCode *mocks.CodeServiceClient) {
				mockCode.
					On("PutGitleaksRepository", mock.Anything, mock.MatchedBy(func(req *code.PutGitleaksRepositoryRequest) bool {
						if req == nil || req.GitleaksRepository == nil {
							return false
						}
						return req.ProjectId == 1 &&
							req.GitleaksRepository.GithubSettingId == 2 &&
							req.GitleaksRepository.RepositoryFullName == "owner/repo" &&
							req.GitleaksRepository.Status == code.Status_OK &&
							req.GitleaksRepository.StatusDetail == "Skipped: repository was already scanned"
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
					On("PutGitleaksRepository", mock.Anything, mock.MatchedBy(func(req *code.PutGitleaksRepositoryRequest) bool {
						return req.GitleaksRepository.Status == code.Status_ERROR &&
							req.GitleaksRepository.StatusDetail == "Skipped: repository size exceeds limit"
					})).
					Return(&emptypb.Empty{}, nil).
					Once()
			},
		},
		{
			name: "API error is only logged",
			repo: &github.Repository{FullName: github.String("owner/repo")},
			prepareMock: func(mockCode *mocks.CodeServiceClient) {
				mockCode.
					On("PutGitleaksRepository", mock.Anything, mock.Anything).
					Return(nil, errors.New("something error")).
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

func TestUpdateGitleaksCache(t *testing.T) {
	scanAt := time.Unix(1710000000, 0)
	tests := []struct {
		name        string
		prepareMock func(*mocks.CodeServiceClient)
		wantErr     bool
	}{
		{
			name: "cache successful scan time",
			prepareMock: func(mockCode *mocks.CodeServiceClient) {
				mockCode.
					On("PutGitleaksCache", mock.Anything, mock.MatchedBy(func(req *code.PutGitleaksCacheRequest) bool {
						return req.ProjectId == 1 &&
							req.GitleaksCache.GithubSettingId == 2 &&
							req.GitleaksCache.RepositoryFullName == "owner/repo" &&
							req.GitleaksCache.ScanAt == scanAt.Unix()
					})).
					Return(&code.PutGitleaksCacheResponse{}, nil).
					Once()
			},
		},
		{
			name: "return cache API error",
			prepareMock: func(mockCode *mocks.CodeServiceClient) {
				mockCode.
					On("PutGitleaksCache", mock.Anything, mock.Anything).
					Return(nil, errors.New("cache error")).
					Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCode := mocks.CodeServiceClient{}
			tt.prepareMock(&mockCode)
			s := sqsHandler{codeClient: &mockCode}

			err := s.updateGitleaksCache(
				context.Background(),
				&message.CodeQueueMessage{ProjectID: 1, GitHubSettingID: 2},
				&github.Repository{FullName: github.String("owner/repo")},
				scanAt,
			)

			if (err != nil) != tt.wantErr {
				t.Fatalf("updateGitleaksCache() error = %v, wantErr %v", err, tt.wantErr)
			}
			mockCode.AssertExpectations(t)
		})
	}
}

func TestGetLastScannedAt(t *testing.T) {
	type GetGitleaksCacheResponse struct {
		Resp *code.GetGitleaksCacheResponse
		Err  error
	}
	type args struct {
		projectID       uint32
		githubSettingID uint32
		repoName        string
	}
	cases := []struct {
		name     string
		args     args
		mockResp *GetGitleaksCacheResponse

		want    *time.Time
		wantErr bool
	}{
		{
			name: "OK no cache",
			args: args{projectID: 1, githubSettingID: 1, repoName: "owner/repo"},
			mockResp: &GetGitleaksCacheResponse{
				Resp: nil,
				Err:  nil,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "OK with cache",
			args: args{projectID: 1, githubSettingID: 1, repoName: "owner/repo"},
			mockResp: &GetGitleaksCacheResponse{
				Resp: &code.GetGitleaksCacheResponse{
					GitleaksCache: &code.GitleaksCache{
						ScanAt: time.Unix(1, 0).Unix(),
					},
				},
				Err: nil,
			},
			want:    func() *time.Time { t := time.Unix(1, 0); return &t }(),
			wantErr: false,
		},
		{
			name: "NG API error",
			args: args{projectID: 1, githubSettingID: 1, repoName: "owner/repo"},
			mockResp: &GetGitleaksCacheResponse{
				Resp: nil,
				Err:  errors.New("something error"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// create mock
			mockCode := mocks.CodeServiceClient{}
			if c.mockResp != nil {
				mockCode.On("GetGitleaksCache", mock.Anything, mock.Anything).Return(c.mockResp.Resp, c.mockResp.Err).Once()
			}
			// create handler
			s := sqsHandler{codeClient: &mockCode, logger: logging.NewLogger()}

			// exec
			got, err := s.getLastScannedAt(context.TODO(), c.args.projectID, c.args.githubSettingID, c.args.repoName)
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error: %+v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
