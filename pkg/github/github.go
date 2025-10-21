package github

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/cenkalti/backoff/v4"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v44/github"
	"golang.org/x/oauth2"
)

const RETRY_NUM uint64 = 3

type GithubServiceClient interface {
	ListRepository(ctx context.Context, config *code.GitHubSetting, repoName string) ([]*github.Repository, error)
	Clone(ctx context.Context, token string, cloneURL string, dstDir string) error
}

type GitHubRepoService interface {
	List(ctx context.Context, user string, opts *github.RepositoryListOptions) ([]*github.Repository, *github.Response, error)
	ListByOrg(ctx context.Context, org string, opts *github.RepositoryListByOrgOptions) ([]*github.Repository, *github.Response, error)
	Get(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error)
}

type GitHubV3Client struct {
	Repositories GitHubRepoService
	*github.Client
}

type riskenGitHubClient struct {
	defaultToken string
	retryer      backoff.BackOff
	logger       logging.Logger
}

func NewGithubClient(defaultToken string, logger logging.Logger) *riskenGitHubClient {
	retry := RETRY_NUM
	return &riskenGitHubClient{
		defaultToken: defaultToken,
		retryer:      backoff.WithMaxRetries(backoff.NewExponentialBackOff(), retry),
		logger:       logger,
	}
}

func (g *riskenGitHubClient) newV3Client(ctx context.Context, token, baseURL string) (*GitHubV3Client, error) {
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: getToken(token, g.defaultToken)},
	))
	client := github.NewClient(httpClient)
	if baseURL != "" { // Default: "https://api.github.com/"
		u, err := url.Parse(baseURL)
		if err != nil {
			return nil, err
		}
		client.BaseURL = u
	}
	return &GitHubV3Client{
		Repositories: client.Repositories,
		Client:       client,
	}, nil
}

func getToken(token, defaultToken string) string {
	if token != "" {
		return token
	}
	return defaultToken
}

func (g *riskenGitHubClient) Clone(ctx context.Context, token string, cloneURL string, dstDir string) error {
	operation := func() error {
		_, err := git.PlainClone(dstDir, false, &git.CloneOptions{
			URL: cloneURL,
			Auth: &http.BasicAuth{
				Username: "dummy", // anything except an empty string
				Password: getToken(token, g.defaultToken),
			},
		})
		return err
	}

	if err := backoff.RetryNotify(operation, g.retryer, g.newRetryLogger(ctx, "github clone")); err != nil {
		return fmt.Errorf("failed to clone %s to %s: %w", cloneURL, dstDir, err)
	}

	return nil
}

func (g *riskenGitHubClient) ListRepository(ctx context.Context, config *code.GitHubSetting, repoName string) ([]*github.Repository, error) {
	client, err := g.newV3Client(ctx, config.PersonalAccessToken, config.BaseUrl)
	if err != nil {
		return nil, fmt.Errorf("create github-v3 client: %w", err)
	}

	// First check if repoName is specified for single repository scan
	if repoName != "" {
		repository, err := g.GetSingleRepository(ctx, client, config, repoName)
		if err != nil {
			return nil, err
		}
		return []*github.Repository{repository}, nil
	}

	// Handle bulk repository scan based on config.Type
	var repos []*github.Repository

	switch config.Type {
	case code.Type_ORGANIZATION:
		repos, err = g.listRepositoryForOrg(ctx, client.Repositories, config)
		if err != nil {
			return repos, err
		}

	case code.Type_USER:
		// Check target user(targetResource) == authenticated user(PAT user)
		user, _, err := client.Client.Users.Get(ctx, "")
		if err != nil {
			return nil, err
		}
		isAuthUser := user.Login != nil && *user.Login == config.TargetResource
		repos, err = g.listRepositoryForUser(ctx, client.Repositories, config, isAuthUser)
		if err != nil {
			return repos, err
		}

	default:
		return nil, fmt.Errorf("unknown github type: type=%s", config.Type.String())
	}

	return repos, nil
}

const (
	githubVisibilityAll string = "all"
)

func (g *riskenGitHubClient) listRepositoryForUser(ctx context.Context, repository GitHubRepoService, config *code.GitHubSetting, isAuthUser bool) ([]*github.Repository, error) {
	repos, err := g.listRepositoryForUserWithOption(ctx, repository, config.TargetResource, isAuthUser)
	if err != nil {
		return nil, err
	}
	return repos, nil
}

func (g *riskenGitHubClient) listRepositoryForUserWithOption(ctx context.Context, repository GitHubRepoService, login string, isAuthUser bool) ([]*github.Repository, error) {
	var allRepo []*github.Repository
	opt := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
		Type:        githubVisibilityAll,
	}

	for {
		var repos []*github.Repository
		var resp *github.Response
		var err error

		if isAuthUser {
			// Use authenticated user endpoint to access private repositories
			repos, resp, err = repository.List(ctx, "", opt)
		} else {
			// Use public user endpoint for other users
			repos, resp, err = repository.List(ctx, login, opt)
		}

		if err != nil {
			return nil, err
		}
		g.logger.Infof(ctx, "Success GitHub API for user repos, %s,login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repos), resp)

		for _, r := range repos {
			// Filter repositories by user owner
			if r.Owner != nil && r.Owner.Login != nil && *r.Owner.Login == login {
				allRepo = append(allRepo, r)
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return allRepo, nil
}

func (g *riskenGitHubClient) listRepositoryForOrg(ctx context.Context, repository GitHubRepoService, config *code.GitHubSetting) ([]*github.Repository, error) {
	repos, err := g.listRepositoryForOrgWithOption(ctx, repository, config.TargetResource)
	if err != nil {
		return nil, err
	}
	return repos, nil
}

func (g *riskenGitHubClient) listRepositoryForOrgWithOption(ctx context.Context, repository GitHubRepoService, login string) ([]*github.Repository, error) {
	var allRepo []*github.Repository
	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
		Type:        githubVisibilityAll,
	}
	for {
		repos, resp, err := repository.ListByOrg(ctx, login, opt)
		if err != nil {
			return nil, err
		}
		g.logger.Infof(ctx, "Success GitHub API for user repos, login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repos), resp)
		allRepo = append(allRepo, repos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return allRepo, nil
}

func (g *riskenGitHubClient) GetSingleRepository(ctx context.Context, client *GitHubV3Client, config *code.GitHubSetting, repoName string) (*github.Repository, error) {
	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository name format: %s, expected 'owner/repo'", repoName)
	}
	owner, repo := parts[0], parts[1]

	// Validate that the repository belongs to the target resource
	if owner != config.TargetResource {
		return nil, fmt.Errorf("repository %s does not belong to %s %s", repoName, config.Type.String(), config.TargetResource)
	}

	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository %s: %w", repoName, err)
	}

	return repository, nil
}

func (t *riskenGitHubClient) newRetryLogger(ctx context.Context, funcName string) func(error, time.Duration) {
	return func(err error, ti time.Duration) {
		t.logger.Warnf(ctx, "[RetryLogger] %s error: duration=%+v, err=%+v", funcName, ti, err)
	}
}
