package gitleaks

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ca-risken/code/pkg/common"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
	"github.com/google/go-github/v44/github"
	"github.com/stretchr/testify/mock"
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

func TestFormatValidationMetadata(t *testing.T) {
	now := time.Unix(123, 0)
	got := formatValidationMetadata(&github.Repository{
		Name:       github.String(" repo "),
		FullName:   github.String("owner/repo"),
		CloneURL:   github.String("https://github.com/owner/repo.git"),
		Visibility: github.String(""),
		HTMLURL:    nil,
		CreatedAt:  &github.Timestamp{Time: now},
	})

	for _, want := range []string{
		`name="repo"`,
		`full_name="owner/repo"`,
		`clone_url="https://github.com/owner/repo.git"`,
		`visibility=""`,
		`html_url=<nil>`,
		`created_at=123`,
		`pushed_at=<nil>`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatValidationMetadata() missing %q in %q", want, got)
		}
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
