package gitleaks

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/ca-risken/datasource-api/proto/code/mocks"
	"github.com/google/go-github/v44/github"
	"github.com/stretchr/testify/mock"
)

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

func TestFilterByNamePattern(t *testing.T) {
	type args struct {
		repos   []*github.Repository
		pattern string
	}
	tests := []struct {
		name string
		args args
		want []*github.Repository
	}{
		{
			name: "Return repositories contained risken in repository name",
			args: args{
				repos: []*github.Repository{
					{
						Name: github.String("risken-core"),
					},
					{
						Name: github.String("core"),
					},
				},
				pattern: "risken",
			},
			want: []*github.Repository{
				{
					Name: github.String("risken-core"),
				},
			},
		},
		{
			name: "Return all repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name: github.String("risken-core"),
					},
					{
						Name: github.String("core"),
					},
				},
				pattern: "",
			},
			want: []*github.Repository{
				{
					Name: github.String("risken-core"),
				},
				{
					Name: github.String("core"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filterByNamePattern(tt.args.repos, tt.args.pattern); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterByNamePattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRecommend(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  *recommend
	}{
		{
			name:  "OK Blank",
			input: "test",
			want: &recommend{
				Risk: `test
		- If a key is leaked, a cyber attack is possible within the scope of the key's authority
		- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
				Recommendation: `Take the following actions for leaked keys
		- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
		- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
		- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getRecommend(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetLastScannedAt(t *testing.T) {
	nowUnix := time.Now().Unix()
	now := time.Unix(nowUnix, 0)
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
			name: "OK",
			args: args{projectID: 1, githubSettingID: 1, repoName: "owner/repo"},
			mockResp: &GetGitleaksCacheResponse{
				Resp: &code.GetGitleaksCacheResponse{
					GitleaksCache: &code.GitleaksCache{
						GithubSettingId:    1,
						RepositoryFullName: "owner/repo",
						ScanAt:             nowUnix,
					},
				},
				Err: nil,
			},
			want:    &now,
			wantErr: false,
		},
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
