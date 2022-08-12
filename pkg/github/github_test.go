package github

import (
	"context"
	"errors"
	"testing"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/google/go-github/v44/github"
)

type fakeGitHubRepoService struct {
	repos []*github.Repository
	resp  *github.Response
	err   error
}

func makeGitHubRepository(name, login string) github.Repository {
	return github.Repository{
		Name: &name,
		Owner: &github.User{
			Login: &login,
		},
	}
}

func PointerString(input string) *string {
	return &input
}

func newfakeGitHubRepoService(empty bool, name, login string, err error) *fakeGitHubRepoService {
	if empty {
		return &fakeGitHubRepoService{
			resp: &github.Response{
				NextPage: 0,
			},
		}
	}
	repo := makeGitHubRepository(name, login)
	return &fakeGitHubRepoService{
		err: err,
		repos: []*github.Repository{
			&repo,
		},
		resp: &github.Response{
			NextPage: 0,
		},
	}
}

func (f *fakeGitHubRepoService) List(ctx context.Context, user string, opts *github.RepositoryListOptions) ([]*github.Repository, *github.Response, error) {
	return f.repos, f.resp, f.err
}
func (f *fakeGitHubRepoService) ListByOrg(ctx context.Context, org string, opts *github.RepositoryListByOrgOptions) ([]*github.Repository, *github.Response, error) {
	return f.repos, f.resp, f.err
}

func Test_listRepositoryForUserWithOption(t *testing.T) {
	cases := []struct {
		name       string
		repository GitHubRepoService
		login      string
		want       []*github.Repository
		wantError  bool
	}{
		{
			name:       "OK",
			login:      "owner",
			repository: newfakeGitHubRepoService(false, "repo", "owner", nil),
			want: []*github.Repository{
				{
					Name:  PointerString("repo"),
					Owner: &github.User{Login: PointerString("onwer")},
				},
			},
		},
		{
			name:       "OK empty",
			repository: newfakeGitHubRepoService(true, "", "", nil),
			want:       []*github.Repository{},
		},
		{
			name:       "NG List Error",
			login:      "owner",
			repository: newfakeGitHubRepoService(false, "", "", errors.New("something error")),
			want:       []*github.Repository{},
			wantError:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			githubClient := newGithubClient("token", logging.NewLogger())
			got, err := githubClient.listRepositoryForUserWithOption(ctx, c.repository, c.login)
			if c.wantError && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantError && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("Unexpected not matching: want=%+v, got=%+v", c.want, got)
			}

		})
	}
}

func Test_listRepositoryForOrgWithOption(t *testing.T) {
	cases := []struct {
		name       string
		repository GitHubRepoService
		login      string
		want       []*github.Repository
		wantError  bool
	}{
		{
			name:       "OK",
			login:      "owner",
			repository: newfakeGitHubRepoService(false, "repo", "owner", nil),
			want: []*github.Repository{
				{
					Name:  PointerString("repo"),
					Owner: &github.User{Login: PointerString("onwer")},
				},
			},
		},
		{
			name:       "OK empty",
			repository: newfakeGitHubRepoService(true, "", "", nil),
			want:       []*github.Repository{},
		},
		{
			name:       "OK empty(owner mismatch)",
			login:      "fakeuser",
			repository: newfakeGitHubRepoService(false, "repo", "owner", nil),
			want:       []*github.Repository{},
		},
		{
			name:       "NG List Error",
			login:      "owner",
			repository: newfakeGitHubRepoService(false, "", "", errors.New("something error")),
			want:       []*github.Repository{},
			wantError:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			githubClient := newGithubClient("token", logging.NewLogger())
			got, err := githubClient.listRepositoryForUserWithOption(ctx, c.repository, c.login)
			if c.wantError && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantError && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("Unexpected not matching: want=%+v, got=%+v", c.want, got)
			}

		})
	}
}
