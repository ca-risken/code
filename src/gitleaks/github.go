package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v44/github"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

type githubServiceClient interface {
	listGitHubEnterpriseOrg(ctx context.Context, config *code.GitHubSetting, enterpriseName string) ([]githubOrganization, error)
	listRepository(ctx context.Context, config *code.GitHubSetting) ([]*github.Repository, error)
	clone(ctx context.Context, token string, cloneURL string, dstDir string) error
}

type githubClient struct {
	defaultToken string
}

func newGithubClient(defaultToken string) githubServiceClient {
	return &githubClient{
		defaultToken: defaultToken,
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

func (g *githubClient) newV4Client(ctx context.Context, token string) *githubv4.Client {
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

type githubOrganization struct {
	Login string
}

func (g *githubClient) listGitHubEnterpriseOrg(ctx context.Context, config *code.GitHubSetting, enterpriseName string) ([]githubOrganization, error) {
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
			appLogger.Errorf(ctx, "GitHub Enterprise API error occured, enterpriseName: %s, err: %+v", enterpriseName, err)
			return nil, err
		}
		allOrg = append(allOrg, q.Enterprise.Organizations.Nodes...)
		if !q.Enterprise.Organizations.PageInfo.HasNextPage {
			break
		}
		variables["orgCursor"] = githubv4.NewString(q.Enterprise.Organizations.PageInfo.EndCursor)
	}
	appLogger.Debugf(ctx, "Got organizations: %+v", q.Enterprise.Organizations.Nodes)
	return allOrg, nil
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
		appLogger.Errorf(ctx, "Failed to create github-v3 client, err=%+v", err)
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
		appLogger.Infof(ctx, "Success GitHub API for user repos, baseURL: %s,login:%s, option:%+v, repo_count: %d, response:%+v", client.BaseURL, login, opt, len(repos), resp)
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
		appLogger.Errorf(ctx, "Failed to create github-v3 client, err=%+v", err)
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
		appLogger.Infof(ctx, "Success GitHub API for user repos, baseURL: %s,login:%s, option:%+v, repo_count: %d, response:%+v", client.BaseURL, login, opt, len(repos), resp)
		allRepo = append(allRepo, repos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return allRepo, nil
}
