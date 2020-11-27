package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/CyberAgent/mimosa-code/proto/code"
	"github.com/google/go-github/v32/github"
	"github.com/kelseyhightower/envconfig"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

type githubServiceClient interface {
	listRepository(ctx context.Context, token string, gitInfo *code.PutGitleaksRequest) ([]*github.Repository, error)
}

type githubClient struct {
	defaultToken string
}

type gihubConfig struct {
	GithubDefaultToken string `required:"true" split_words:"true"`
}

func newGithubClient() githubServiceClient {
	var conf gihubConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Could not read githubConfig. err: %+v", err)
	}
	return &githubClient{
		defaultToken: conf.GithubDefaultToken,
	}
}

func (g *githubClient) newV3Client(ctx context.Context, token string) *github.Client {
	githubToken := g.defaultToken
	if token != "" {
		githubToken = token
	}
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	))
	return github.NewClient(httpClient)
}

func (g *githubClient) newV4Client(ctx context.Context, token string) *githubv4.Client {
	githubToken := g.defaultToken
	if token != "" {
		githubToken = token
	}
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	))
	return githubv4.NewClient(httpClient)
}

func (g *githubClient) listRepository(ctx context.Context, token string, gitInfo *code.PutGitleaksRequest) ([]*github.Repository, error) {
	var repos []*github.Repository
	var err error
	switch gitInfo.Gitleaks.Type {
	case code.Type_ENTERPRISE:
		repos, err = g.listEnterpriseRepository(ctx, token, gitInfo.Gitleaks.TargetResource)
		if err != nil {
			return repos, err
		}
	case code.Type_ORGANIZATION:
		repos, err = g.listRepositoryForOrg(ctx, token, gitInfo.Gitleaks.TargetResource)
		if err != nil {
			return repos, err
		}
	case code.Type_USER:
		repos, err = g.listRepositoryForUser(ctx, token, gitInfo.Gitleaks.TargetResource)
		if err != nil {
			return repos, err
		}
	default:
		return nil, fmt.Errorf("Unknown github type: type=%+v", gitInfo.Gitleaks.Type)
	}
	return filterRepository(repos, gitInfo.Gitleaks.RepositoryPattern), nil
}

type githubOrganization struct {
	Login string
}

func (g *githubClient) listEnterpriseRepository(ctx context.Context, token, enterpriseName string) ([]*github.Repository, error) {
	client := g.newV4Client(ctx, token)
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
			appLogger.Errorf("GitHub Enterprise API error occured, enterpriseName: %s, err: %+v", enterpriseName, err)
			return nil, err
		}
		allOrg = append(allOrg, q.Enterprise.Organizations.Nodes...)
		if !q.Enterprise.Organizations.PageInfo.HasNextPage {
			break
		}
		variables["orgCursor"] = githubv4.NewString(q.Enterprise.Organizations.PageInfo.EndCursor)
	}
	appLogger.Debugf("Got organizations: %+v", q.Enterprise.Organizations.Nodes)

	var allRepo []*github.Repository
	for _, org := range allOrg {
		repos, err := g.listRepositoryForOrg(ctx, token, org.Login)
		if err != nil {
			return nil, err
		}
		allRepo = append(allRepo, repos...)
	}
	return allRepo, nil
}

const (
	githubVisibilityPublic   string = "public"
	githubVisibilityInternal string = "internal"
	githubVisibilityPrivate  string = "private"
)

func (g *githubClient) listRepositoryForUser(ctx context.Context, token, login string) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	// public
	repos, err := g.listRepositoryForUserWithOption(ctx, token, login, githubVisibilityPublic)
	if err != nil {
		return nil, err
	}
	allRepos = append(allRepos, repos...)

	// private
	if token == "" {
		return allRepos, nil // skip private repository
	}
	repos, err = g.listRepositoryForUserWithOption(ctx, token, login, githubVisibilityPrivate)
	if err != nil {
		return nil, err
	}
	allRepos = append(allRepos, repos...)
	return allRepos, nil
}

func (g *githubClient) listRepositoryForUserWithOption(ctx context.Context, token, login, visibility string) ([]*github.Repository, error) {
	client := g.newV3Client(ctx, token)
	var repos []*github.Repository
	opt := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
		Type:        visibility,
	}
	for {
		repo, resp, err := client.Repositories.List(ctx, login, opt)
		if err != nil {
			return nil, err
		}
		appLogger.Debugf("Success GitHub API for user repos, login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repo), resp)
		repos = append(repos, repo...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return repos, nil
}

func (g *githubClient) listRepositoryForOrg(ctx context.Context, token, login string) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	// public
	repos, err := g.listRepositoryForOrgWithOption(ctx, token, login, githubVisibilityPublic)
	if err != nil {
		return nil, err
	}
	allRepos = append(allRepos, repos...)

	// internal
	repos, err = g.listRepositoryForOrgWithOption(ctx, token, login, githubVisibilityInternal)
	if err != nil {
		return nil, err
	}
	allRepos = append(allRepos, repos...)

	// private
	if token == "" {
		return allRepos, nil // skip private repository
	}
	repos, err = g.listRepositoryForOrgWithOption(ctx, token, login, githubVisibilityPrivate)
	if err != nil {
		return nil, err
	}
	allRepos = append(allRepos, repos...)
	return allRepos, nil
}

func (g *githubClient) listRepositoryForOrgWithOption(ctx context.Context, token, login, visibility string) ([]*github.Repository, error) {
	appLogger.Debugf("token: %s", token) //delete
	client := g.newV3Client(ctx, token)
	var repos []*github.Repository
	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
		Type:        visibility,
	}
	for {
		repo, resp, err := client.Repositories.ListByOrg(ctx, login, opt)
		if err != nil {
			return nil, err
		}
		appLogger.Debugf("Success GitHub API for organization repos, login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repo), resp)
		repos = append(repos, repo...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return repos, nil
}

func filterRepository(repos []*github.Repository, pattern string) []*github.Repository {
	var filteredRepos []*github.Repository
	for _, repo := range repos {
		if strings.Contains(*repo.Name, pattern) {
			filteredRepos = append(filteredRepos, repo)
		}
	}
	return filteredRepos
}
