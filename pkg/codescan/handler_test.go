package codescan

import (
	"context"
	"reflect"
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

func TestFilterByVisibility(t *testing.T) {
	visibilityPublic := "public"
	visibilityInternal := "internal"
	visibilityPrivate := "private"
	type args struct {
		repos        []*github.Repository
		scanPublic   bool
		scanInternal bool
		scanPrivate  bool
	}
	tests := []struct {
		name string
		args args
		want []*github.Repository
	}{
		{
			name: "Return public repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanPublic: true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("public-repo"),
					Visibility: &visibilityPublic,
				},
			},
		},
		{
			name: "Return internal repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanInternal: true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("internal-repo"),
					Visibility: &visibilityInternal,
				},
			},
		},
		{
			name: "Return private repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanPrivate: true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("private-repo"),
					Visibility: &visibilityPrivate,
				},
			},
		},
		{
			name: "Return all repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanPublic:   true,
				scanInternal: true,
				scanPrivate:  true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("public-repo"),
					Visibility: &visibilityPublic,
				},
				{
					Name:       github.String("internal-repo"),
					Visibility: &visibilityInternal,
				},
				{
					Name:       github.String("private-repo"),
					Visibility: &visibilityPrivate,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filterByVisibility(tt.args.repos, tt.args.scanPublic, tt.args.scanInternal, tt.args.scanPrivate); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterByRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}
