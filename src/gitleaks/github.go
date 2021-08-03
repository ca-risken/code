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
	listEnterpriseOrg(ctx context.Context, config *code.Gitleaks, enterpriseName string) (*[]githubOrganization, error)
	listRepository(ctx context.Context, config *code.Gitleaks, findings *[]repositoryFinding) error
}

type githubClient struct {
	defaultToken string
}

type gihubConfig struct {
	GithubDefaultToken    string `required:"true" split_words:"true"`
	LimitRepositorySizeKb int    `required:"true" split_words:"true"`
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
	ID                  *int64           `json:"id,omitempty"`
	NodeID              *string          `json:"node_id,omitempty"`
	Name                *string          `json:"name,omitempty"`
	FullName            *string          `json:"full_name,omitempty"`
	Description         *string          `json:"description,omitempty"`
	Homepage            *string          `json:"homepage,omitempty"`
	CloneURL            *string          `json:"clone_url,omitempty"`
	GitURL              *string          `json:"git_url,omitempty"`
	MirrorURL           *string          `json:"mirror_url,omitempty"`
	SSHURL              *string          `json:"ssh_url,omitempty"`
	Language            *string          `json:"language,omitempty"`
	Fork                *bool            `json:"fork,omitempty"`
	ForksCount          *int             `json:"forks_count,omitempty"`
	NetworkCount        *int             `json:"network_count,omitempty"`
	OpenIssuesCount     *int             `json:"open_issues_count,omitempty"`
	StargazersCount     *int             `json:"stargazers_count,omitempty"`
	SubscribersCount    *int             `json:"subscribers_count,omitempty"`
	WatchersCount       *int             `json:"watchers_count,omitempty"`
	Size                *int             `json:"size,omitempty"`
	AutoInit            *bool            `json:"auto_init,omitempty"`
	AllowRebaseMerge    *bool            `json:"allow_rebase_merge,omitempty"`
	AllowSquashMerge    *bool            `json:"allow_squash_merge,omitempty"`
	AllowMergeCommit    *bool            `json:"allow_merge_commit,omitempty"`
	DeleteBranchOnMerge *bool            `json:"delete_branch_on_merge,omitempty"`
	Topics              []string         `json:"topics,omitempty"`
	Archived            *bool            `json:"archived,omitempty"`
	Disabled            *bool            `json:"disabled,omitempty"`
	Permissions         *map[string]bool `json:"permissions,omitempty"`
	Private             *bool            `json:"private,omitempty"`
	HasIssues           *bool            `json:"has_issues,omitempty"`
	HasWiki             *bool            `json:"has_wiki,omitempty"`
	HasPages            *bool            `json:"has_pages,omitempty"`
	HasProjects         *bool            `json:"has_projects,omitempty"`
	HasDownloads        *bool            `json:"has_downloads,omitempty"`
	IsTemplate          *bool            `json:"is_template,omitempty"`
	LicenseTemplate     *string          `json:"license_template,omitempty"`
	GitignoreTemplate   *string          `json:"gitignore_template,omitempty"`
	TeamID              *int64           `json:"team_id,omitempty"`
	Visibility          *string          `json:"visibility,omitempty"`

	CreatedAt *github.Timestamp `json:"created_at,omitempty"`
	PushedAt  *github.Timestamp `json:"pushed_at,omitempty"`
	UpdatedAt *github.Timestamp `json:"updated_at,omitempty"`

	LeakFindings []*leakFinding `json:"leak_findings,omitempty"`
	LastScanedAt time.Time      `json:"last_scaned_at"`
	SkipScan     bool           `json:"skip_scan"`
}

func (r *repositoryFinding) alreadyScaned() bool {
	if r.PushedAt != nil {
		return r.PushedAt.Time.Unix() <= r.LastScanedAt.Unix()
	}
	return false
}

func (g *githubClient) listRepository(ctx context.Context, config *code.Gitleaks, findings *[]repositoryFinding) error {
	var repos []*github.Repository
	var err error
	switch config.Type {
	case code.Type_ORGANIZATION:
		repos, err = g.listRepositoryForOrg(ctx, config, config.TargetResource)
		if err != nil {
			return err
		}
	case code.Type_USER:
		repos, err = g.listRepositoryForUser(ctx, config, config.TargetResource)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("Unknown github type: type=%+v", config.Type)
	}
	setRepositoryFinding(repos, config.RepositoryPattern, findings)
	return nil
}

type githubOrganization struct {
	Login string
}

func (g *githubClient) listEnterpriseOrg(ctx context.Context, config *code.Gitleaks, enterpriseName string) (*[]githubOrganization, error) {
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
	return &allOrg, nil
}

const (
	githubVisibilityPublic   string = "public"
	githubVisibilityInternal string = "internal"
	githubVisibilityPrivate  string = "private"
)

func (g *githubClient) listRepositoryForUser(ctx context.Context, config *code.Gitleaks, login string) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	// public
	if config.ScanPublic {
		ghVisibility := githubVisibilityPublic
		repos, err := g.listRepositoryForUserWithOption(ctx, config.PersonalAccessToken, login, ghVisibility)
		if err != nil {
			return nil, err
		}
		allRepos = append(allRepos, repos...)
	}

	// private
	if config.ScanPrivate {
		ghVisibility := githubVisibilityPrivate
		repos, err := g.listRepositoryForUserWithOption(ctx, config.PersonalAccessToken, login, ghVisibility)
		if err != nil {
			return nil, err
		}
		allRepos = append(allRepos, repos...)
	}
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
		appLogger.Infof("Success GitHub API for user repos, login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repos), resp)
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

func (g *githubClient) listRepositoryForOrg(ctx context.Context, config *code.Gitleaks, login string) ([]*github.Repository, error) {
	var allRepos []*github.Repository
	// public
	if config.ScanPublic {
		ghVisibility := githubVisibilityPublic
		repos, err := g.listRepositoryForOrgWithOption(ctx, config.PersonalAccessToken, login, ghVisibility)
		if err != nil {
			return nil, err
		}
		allRepos = append(allRepos, repos...)
	}

	// internal
	if config.ScanInternal {
		ghVisibility := githubVisibilityInternal
		repos, err := g.listRepositoryForOrgWithOption(ctx, config.PersonalAccessToken, login, ghVisibility)
		if err != nil {
			return nil, err
		}
		allRepos = append(allRepos, repos...)
	}

	// private
	if config.ScanPrivate {
		ghVisibility := githubVisibilityPrivate
		repos, err := g.listRepositoryForOrgWithOption(ctx, config.PersonalAccessToken, login, ghVisibility)
		if err != nil {
			return nil, err
		}
		allRepos = append(allRepos, repos...)
	}
	return allRepos, nil
}

func (g *githubClient) listRepositoryForOrgWithOption(ctx context.Context, token, login, visibility string) ([]*github.Repository, error) {
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
		appLogger.Infof("Success GitHub API for organization repos, login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repos), resp)
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
				ID:                  repo.ID,
				NodeID:              repo.NodeID,
				Name:                repo.Name,
				FullName:            repo.FullName,
				Description:         repo.Description,
				Homepage:            repo.Homepage,
				CloneURL:            repo.CloneURL,
				GitURL:              repo.GitURL,
				MirrorURL:           repo.MirrorURL,
				SSHURL:              repo.SSHURL,
				Language:            repo.Language,
				Fork:                repo.Fork,
				ForksCount:          repo.ForksCount,
				NetworkCount:        repo.NetworkCount,
				OpenIssuesCount:     repo.OpenIssuesCount,
				StargazersCount:     repo.StargazersCount,
				SubscribersCount:    repo.SubscribersCount,
				WatchersCount:       repo.WatchersCount,
				Size:                repo.Size,
				AutoInit:            repo.AutoInit,
				AllowRebaseMerge:    repo.AllowRebaseMerge,
				AllowSquashMerge:    repo.AllowSquashMerge,
				AllowMergeCommit:    repo.AllowMergeCommit,
				DeleteBranchOnMerge: repo.DeleteBranchOnMerge,
				Topics:              repo.Topics,
				Archived:            repo.Archived,
				Disabled:            repo.Disabled,
				Permissions:         repo.Permissions,
				Private:             repo.Private,
				HasIssues:           repo.HasIssues,
				HasWiki:             repo.HasWiki,
				HasPages:            repo.HasPages,
				HasProjects:         repo.HasProjects,
				HasDownloads:        repo.HasDownloads,
				IsTemplate:          repo.IsTemplate,
				LicenseTemplate:     repo.LicenseTemplate,
				GitignoreTemplate:   repo.GitignoreTemplate,
				TeamID:              repo.TeamID,
				Visibility:          repo.Visibility,

				CreatedAt: repo.CreatedAt,
				PushedAt:  repo.PushedAt,
				UpdatedAt: repo.UpdatedAt,
			})
		}
	}
}
