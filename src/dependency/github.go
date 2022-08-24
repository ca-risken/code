package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v44/github"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

type githubServiceClient interface {
	ListGitHubEnterpriseOrg(ctx context.Context, config *code.GitHubSetting, enterpriseName string) ([]githubOrganization, error)
	ListRepository(ctx context.Context, config *code.GitHubSetting) ([]*github.Repository, error)
	Clone(ctx context.Context, token string, cloneURL string, dstDir string) error
}

type GitHubRepoService interface {
	List(ctx context.Context, user string, opts *github.RepositoryListOptions) ([]*github.Repository, *github.Response, error)
	ListByOrg(ctx context.Context, org string, opts *github.RepositoryListByOrgOptions) ([]*github.Repository, *github.Response, error)
}

type GitHubQueryService interface {
	Query(ctx context.Context, q interface{}, variables map[string]interface{}) error
}

type GitHubV3Client struct {
	Repositories GitHubRepoService
	*github.Client
}

type riskenGitHubClient struct {
	defaultToken string
	logger       logging.Logger
}

func newGithubClient(defaultToken string, logger logging.Logger) *riskenGitHubClient {
	return &riskenGitHubClient{
		defaultToken: defaultToken,
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
	return &GitHubV3Client{Repositories: client.Repositories}, nil
}

func (g *riskenGitHubClient) newV4Client(ctx context.Context, token string) *githubv4.Client {
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: getToken(token, g.defaultToken)},
	))
	return githubv4.NewClient(httpClient)
}

func getToken(token, defaultToken string) string {
	if token != "" {
		return token
	}
	return defaultToken
}

func (g *riskenGitHubClient) Clone(ctx context.Context, token string, cloneURL string, dstDir string) error {
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

func (g *riskenGitHubClient) ListRepository(ctx context.Context, config *code.GitHubSetting) ([]*github.Repository, error) {
	var repos []*github.Repository
	var err error
	client, err := g.newV3Client(ctx, config.PersonalAccessToken, config.BaseUrl)
	if err != nil {
		return nil, fmt.Errorf("create github-v3 client: %w", err)
	}
	switch config.Type {
	case code.Type_ORGANIZATION:
		repos, err = g.listRepositoryForOrg(ctx, client.Repositories, config)
		if err != nil {
			return repos, err
		}
	case code.Type_USER:
		repos, err = g.listRepositoryForUser(ctx, client.Repositories, config)
		if err != nil {
			return repos, err
		}
	default:
		return repos, fmt.Errorf("unknown github type: type=%s", config.Type.String())
	}

	return repos, nil
}

type githubOrganization struct {
	Login string
}

func (g *riskenGitHubClient) ListGitHubEnterpriseOrg(ctx context.Context, config *code.GitHubSetting, enterpriseName string) ([]githubOrganization, error) {
	client := g.newV4Client(ctx, config.PersonalAccessToken)
	var q struct {
		Enterprise struct {
			Organizations struct {
				Nodes    []githubOrganization
				PageInfo struct {
					EndCursor   githubv4.String
					HasNextPage bool
				}
			} `graphql:"organizations(first: 100, after: $orgCursor)"` // 100 per page.
		} `graphql:"enterprise(slug: $enterpriseName)"`
	}
	variables := map[string]interface{}{
		"enterpriseName": githubv4.String(enterpriseName),
		"orgCursor":      (*githubv4.String)(nil), // Null after argument to get first page.
	}

	var allOrg []githubOrganization
	for {
		if err := client.Query(ctx, &q, variables); err != nil {
			g.logger.Errorf(ctx, "GitHub Enterprise API error occured, enterpriseName: %s, err: %+v", enterpriseName, err)
			return nil, fmt.Errorf("GitHub Enterprise API error: %w", err)
		}
		allOrg = append(allOrg, q.Enterprise.Organizations.Nodes...)
		if !q.Enterprise.Organizations.PageInfo.HasNextPage {
			break
		}
		variables["orgCursor"] = githubv4.NewString(q.Enterprise.Organizations.PageInfo.EndCursor)
	}
	g.logger.Debugf(ctx, "Got organizations: %+v", q.Enterprise.Organizations.Nodes)
	return allOrg, nil
}

const (
	githubVisibilityAll string = "all"
)

func (g *riskenGitHubClient) listRepositoryForUser(ctx context.Context, repository GitHubRepoService, config *code.GitHubSetting) ([]*github.Repository, error) {
	repos, err := g.listRepositoryForUserWithOption(ctx, repository, config.TargetResource)
	if err != nil {
		return nil, err
	}
	return repos, nil
}

func (g *riskenGitHubClient) listRepositoryForUserWithOption(ctx context.Context, repository GitHubRepoService, login string) ([]*github.Repository, error) {
	var allRepo []*github.Repository
	opt := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
		Type:        githubVisibilityAll,
	}
	for {
		repos, resp, err := repository.List(ctx, "", opt) // user: Passing the empty string will list repositories for the authenticated user.
		if err != nil {
			return nil, err
		}
		g.logger.Infof(ctx, "Success GitHub API for user repos, %s,login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repos), resp)
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
