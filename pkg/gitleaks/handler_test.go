package gitleaks

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
	"github.com/google/go-github/v44/github"
	"github.com/stretchr/testify/mock"
)

func TestGetRepositoriesFromCodeQueueMessage(t *testing.T) {
	t.Run("Repository metadata exists", func(t *testing.T) {
		now := time.Now().Unix()
		msg := &message.CodeQueueMessage{
			Repository: &message.RepositoryMetadata{
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
		}
		repos := getRepositoriesFromCodeQueueMessage(msg)
		if len(repos) != 1 {
			t.Fatalf("unexpected repository count: %+v", len(repos))
		}
		if repos[0].GetFullName() != "owner/repo" {
			t.Fatalf("unexpected full_name: %+v", repos[0].GetFullName())
		}
		if repos[0].GetCloneURL() != "https://github.com/owner/repo.git" {
			t.Fatalf("unexpected clone_url: %+v", repos[0].GetCloneURL())
		}
	})

	t.Run("Repository metadata is nil", func(t *testing.T) {
		repos := getRepositoriesFromCodeQueueMessage(&message.CodeQueueMessage{})
		if len(repos) != 0 {
			t.Fatalf("unexpected repository count: %+v", len(repos))
		}
	})
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
	if err := validateRepository(repo, ""); err != nil {
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
			name:    "host mismatch",
			repo:    func() *github.Repository { r := *baseRepo; r.CloneURL = github.String("https://evil.example.com/owner/repo.git"); return &r }(),
			baseURL: "https://api.github.com/",
			wantErr: true,
		},
		{
			name:    "path mismatch",
			repo:    func() *github.Repository { r := *baseRepo; r.CloneURL = github.String("https://github.com/owner/other.git"); return &r }(),
			baseURL: "",
			wantErr: true,
		},
		{
			name:    "enterprise host accepted",
			repo:    func() *github.Repository { r := *baseRepo; r.CloneURL = github.String("https://github.example.com/owner/repo.git"); return &r }(),
			baseURL: "https://github.example.com/api/v3/",
			wantErr: false,
		},
		{
			name:    "html_url invalid scheme",
			repo:    func() *github.Repository { r := *baseRepo; r.HTMLURL = github.String("http://github.com/owner/repo"); return &r }(),
			baseURL: "",
			wantErr: true,
		},
		{
			name:    "html_url host mismatch",
			repo:    func() *github.Repository { r := *baseRepo; r.HTMLURL = github.String("https://evil.example.com/owner/repo"); return &r }(),
			baseURL: "https://api.github.com/",
			wantErr: true,
		},
		{
			name:    "html_url path mismatch",
			repo:    func() *github.Repository { r := *baseRepo; r.HTMLURL = github.String("https://github.com/owner/other"); return &r }(),
			baseURL: "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRepository(tt.repo, tt.baseURL)
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
