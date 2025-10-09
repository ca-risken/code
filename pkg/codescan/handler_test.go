package codescan

import (
	"context"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/google/go-github/v44/github"
)

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
			if got := s.skipScan(tt.args.ctx, tt.args.repo, tt.args.limitRepositorySize); got != tt.want {
				t.Errorf("skipScan() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetRepositoryNameFromMessage tests the repository name extraction from message
func TestGetRepositoryNameFromMessage(t *testing.T) {
	type testMessage struct {
		ProjectID       uint32
		GitHubSettingID uint32
		RepositoryName  string
		ScanOnly        bool
	}

	type args struct {
		msg interface{}
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Message with RepositoryName",
			args: args{
				msg: &testMessage{
					ProjectID:       1001,
					GitHubSettingID: 1001,
					RepositoryName:  "owner/repo-name",
					ScanOnly:        true,
				},
			},
			want: "owner/repo-name",
		},
		{
			name: "Message without RepositoryName",
			args: args{
				msg: &testMessage{
					ProjectID:       1001,
					GitHubSettingID: 1001,
					ScanOnly:        true,
				},
			},
			want: "",
		},
		{
			name: "Nil message",
			args: args{
				msg: nil,
			},
			want: "",
		},
		{
			name: "Non-struct message",
			args: args{
				msg: "string message",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRepositoryNameFromMessage(tt.args.msg); got != tt.want {
				t.Errorf("getRepositoryNameFromMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetProjectIDFromMessage tests the project ID extraction from message
func TestGetProjectIDFromMessage(t *testing.T) {
	type testMessage struct {
		ProjectID       uint32
		GitHubSettingID uint32
		RepositoryName  string
		ScanOnly        bool
	}

	type args struct {
		msg interface{}
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
		{
			name: "Message with ProjectID",
			args: args{
				msg: &testMessage{
					ProjectID:       1001,
					GitHubSettingID: 1001,
					RepositoryName:  "owner/repo-name",
					ScanOnly:        true,
				},
			},
			want: 1001,
		},
		{
			name: "Message without ProjectID",
			args: args{
				msg: &testMessage{
					GitHubSettingID: 1001,
					RepositoryName:  "owner/repo-name",
					ScanOnly:        true,
				},
			},
			want: 0,
		},
		{
			name: "Nil message",
			args: args{
				msg: nil,
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getProjectIDFromMessage(tt.args.msg); got != tt.want {
				t.Errorf("getProjectIDFromMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}
