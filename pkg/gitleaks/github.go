package gitleaks

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v44/github"
	"golang.org/x/oauth2"
)

type githubServiceClient interface {
	listRepository(ctx context.Context, config *code.GitHubSetting) ([]*github.Repository, error)
	clone(ctx context.Context, token string, cloneURL string, dstDir string) error
}

type githubClient struct {
	defaultToken string
	logger       logging.Logger
}

func newGithubClient(defaultToken string, logger logging.Logger) githubServiceClient {
	return &githubClient{
		defaultToken: defaultToken,
		logger:       logger,
	}
}

func (g *githubClient) newV3Client(ctx context.Context, token, baseURL string) (*github.Client, error) {
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
	return client, nil
}

func getToken(token, defaultToken string) string {
	if token != "" {
		return token
	}
	return defaultToken
}

func (g *githubClient) clone(ctx context.Context, token string, cloneURL string, dstDir string) error {
	_, err := git.PlainClone(dstDir, false, &git.CloneOptions{
		URL: cloneURL,
		Auth: &http.BasicAuth{
			Username: "dummy", // anything except an empty string
			Password: getToken(token, g.defaultToken),
		},
	})

	if err != nil {
		return fmt.Errorf("failed to clone %s to %s: %w", cloneURL, dstDir, err)
	}

	return nil
}

func (g *githubClient) listRepository(ctx context.Context, config *code.GitHubSetting) ([]*github.Repository, error) {
	var repos []*github.Repository
	var err error
	switch config.Type {
	case code.Type_ORGANIZATION:
		repos, err = g.listRepositoryForOrg(ctx, config)
		if err != nil {
			return repos, err
		}
	case code.Type_USER:
		repos, err = g.listRepositoryForUser(ctx, config)
		if err != nil {
			return repos, err
		}
	default:
		return repos, fmt.Errorf("unknown github type: type=%s", config.Type.String())
	}

	return repos, nil
}

const (
	githubVisibilityPublic   string = "public"
	githubVisibilityInternal string = "internal"
	githubVisibilityPrivate  string = "private"
	githubVisibilityAll      string = "all"
)

func (g *githubClient) listRepositoryForUser(ctx context.Context, config *code.GitHubSetting) ([]*github.Repository, error) {
	var repos []*github.Repository
	allRepos, err := g.listRepositoryForUserWithOption(ctx, config.BaseUrl, config.PersonalAccessToken, config.TargetResource, githubVisibilityAll)
	if err != nil {
		return nil, err
	}
	for _, r := range allRepos {
		if config.GitleaksSetting.ScanPublic && *r.Visibility == githubVisibilityPublic {
			repos = append(repos, r) // public
		} else if config.GitleaksSetting.ScanPrivate && *r.Visibility == githubVisibilityPrivate {
			repos = append(repos, r) // private
		}
	}
	return repos, nil
}

func (g *githubClient) listRepositoryForUserWithOption(ctx context.Context, baseURL, token, login, visibility string) ([]*github.Repository, error) {
	client, err := g.newV3Client(ctx, token, baseURL)
	if err != nil {
		g.logger.Errorf(ctx, "Failed to create github-v3 client, err=%+v", err)
		return nil, err
	}
	var allRepo []*github.Repository
	opt := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
		Type:        visibility,
	}
	for {
		repos, resp, err := client.Repositories.List(ctx, "", opt) // user: Passing the empty string will list repositories for the authenticated user.
		if err != nil {
			return nil, err
		}
		g.logger.Infof(ctx, "Success GitHub API for user repos, baseURL: %s,login:%s, option:%+v, repo_count: %d, response:%+v", client.BaseURL, login, opt, len(repos), resp)
		for _, r := range repos {
			if *r.Owner.Login == login {
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

func (g *githubClient) listRepositoryForOrg(ctx context.Context, config *code.GitHubSetting) ([]*github.Repository, error) {
	var repos []*github.Repository
	allRepos, err := g.listRepositoryForOrgWithOption(ctx, config.BaseUrl, config.PersonalAccessToken, config.TargetResource, githubVisibilityAll)
	if err != nil {
		return nil, err
	}
	for _, r := range allRepos {
		if config.GitleaksSetting.ScanPublic && *r.Visibility == githubVisibilityPublic {
			repos = append(repos, r) // public
		} else if config.GitleaksSetting.ScanInternal && *r.Visibility == githubVisibilityInternal {
			repos = append(repos, r) // internal
		} else if config.GitleaksSetting.ScanPrivate && *r.Visibility == githubVisibilityPrivate {
			repos = append(repos, r) // private
		}
	}
	return repos, nil
}

func (g *githubClient) listRepositoryForOrgWithOption(ctx context.Context, baseURL, token, login, visibility string) ([]*github.Repository, error) {
	client, err := g.newV3Client(ctx, token, baseURL)
	if err != nil {
		g.logger.Errorf(ctx, "Failed to create github-v3 client, err=%+v", err)
		return nil, err
	}

	var allRepo []*github.Repository
	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
		Type:        visibility,
	}
	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, login, opt)
		if err != nil {
			return nil, err
		}
		g.logger.Infof(ctx, "Success GitHub API for user repos, baseURL: %s,login:%s, option:%+v, repo_count: %d, response:%+v", client.BaseURL, login, opt, len(repos), resp)
		allRepo = append(allRepo, repos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return allRepo, nil
}