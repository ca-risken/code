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
			wantLen: 0,
			want:    nil,
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
			want:    nil,
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
		On("PutGitleaksRepository", mock.Anything, mock.MatchedBy(func(req *code.PutGitleaksRepositoryRequest) bool {
			if req == nil || req.GitleaksRepository == nil {
				return false
			}
			return req.ProjectId == 1 &&
				req.GitleaksRepository.GithubSettingId == 2 &&
				req.GitleaksRepository.RepositoryFullName == "owner/repo" &&
				req.GitleaksRepository.Status == code.Status_ERROR
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
		GitleaksSetting: &code.GitleaksSetting{},
	}

	err := s.handleRepositoryScan(ctx, msg, setting, "token", "req-1", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	mockCode.AssertExpectations(t)
}

func TestValidateRepository(t *testing.T) {
	repo := &github.Repository{
		Name:       github.String("repo"),
		FullName:   github.String("owner/repo"),
		CloneURL:   github.String("https://github.com/owner/repo.git"),
		Visibility: github.String("private"),
		HTMLURL:    github.String("https://github.com/owner/repo"),
		CreatedAt: &github.Timestamp{
			Time: time.Now().Add(-1 * time.Hour),
		},
		PushedAt: &github.Timestamp{
			Time: time.Now(),
		},
	}
	if err := common.ValidateRepository(repo, ""); err != nil {
		t.Fatalf("unexpected error: %+v", err)
	}
}

func TestValidateRepository_CloneURLValidation(t *testing.T) {
	baseRepo := &github.Repository{
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
			if got := s.skipScan(tt.args.ctx, tt.args.repo, tt.args.lastScannedAt, tt.args.limitRepositorySize); got != tt.want {
				t.Errorf("skipScan() = %v, want %v", got, tt.want)
			}
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
