package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CyberAgent/mimosa-code/proto/code"
	"github.com/google/go-github/v32/github"
	"github.com/kelseyhightower/envconfig"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

type githubServiceClient interface {
	listRepository(ctx context.Context, githubType code.Type, target, filter, token string, findings *[]repositoryFinding) error
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
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: getToken(token, g.defaultToken)},
	))
	return github.NewClient(httpClient)
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

type repositoryFinding struct {
	ID          *int64            `json:"id,omitempty"`
	Name        *string           `json:"name,omitempty"`
	FullName    *string           `json:"full_name,omitempty"`
	Description *string           `json:"description,omitempty"`
	CloneURL    *string           `json:"clone_url,omitempty"`
	Fork        *bool             `json:"fork,omitempty"`
	Archived    *bool             `json:"archived,omitempty"`
	Disabled    *bool             `json:"disabled,omitempty"`
	Visibility  *string           `json:"visibility,omitempty"`
	CreatedAt   *github.Timestamp `json:"created_at,omitempty"`
	PushedAt    *github.Timestamp `json:"pushed_at,omitempty"`
	UpdatedAt   *github.Timestamp `json:"updated_at,omitempty"`

	LeakFindings []*leakFinding `json:"leak_findings,omitempty"`
	LastScanedAt time.Time      `json:"last_scaned_at"`
}

func (r *repositoryFinding) alreadyScaned() bool {
	if r.PushedAt != nil {
		return r.PushedAt.Time.Unix() <= r.LastScanedAt.Unix()
	}
	return false
}

func (g *githubClient) listRepository(ctx context.Context, githubType code.Type, target, filter, token string, findings *[]repositoryFinding) error {
	var repos []*github.Repository
	var err error
	switch githubType {
	case code.Type_ENTERPRISE:
		repos, err = g.listEnterpriseRepository(ctx, token, target)
		if err != nil {
			return err
		}
	case code.Type_ORGANIZATION:
		repos, err = g.listRepositoryForOrg(ctx, token, target)
		if err != nil {
			return err
		}
	case code.Type_USER:
		repos, err = g.listRepositoryForUser(ctx, token, target)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Unknown github type: type=%+v", githubType)
	}
	setRepositoryFinding(repos, filter, findings)
	return nil
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
	var allRepo []*github.Repository
	opt := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
		Type:        visibility,
	}
	for {
		repos, resp, err := client.Repositories.List(ctx, login, opt)
		if err != nil {
			return nil, err
		}
		appLogger.Debugf("Success GitHub API for user repos, login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repos), resp)
		for _, r := range repos {
			r.Visibility = &visibility
		}
		allRepo = append(allRepo, repos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return allRepo, nil
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
		appLogger.Debugf("Success GitHub API for organization repos, login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repos), resp)
		for _, r := range repos {
			r.Visibility = &visibility
		}
		allRepo = append(allRepo, repos...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return allRepo, nil
}

func setRepositoryFinding(repos []*github.Repository, pattern string, findings *[]repositoryFinding) {
	for _, repo := range repos {
		if strings.Contains(*repo.Name, pattern) {
			*findings = append(*findings, repositoryFinding{
				ID:          repo.ID,
				Name:        repo.Name,
				FullName:    repo.FullName,
				Description: repo.Description,
				CloneURL:    repo.CloneURL,
				Fork:        repo.Fork,
				Archived:    repo.Archived,
				Disabled:    repo.Disabled,
				Visibility:  repo.Visibility,
				CreatedAt:   repo.CreatedAt,
				PushedAt:    repo.PushedAt,
				UpdatedAt:   repo.UpdatedAt,
			})
		}
	}
}
