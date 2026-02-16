package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/cenkalti/backoff/v4"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v44/github"
	"golang.org/x/oauth2"
)

const (
	RETRY_NUM        uint64        = 3
	repoListCacheTTL               = 10 * time.Minute
)

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

type repoListCacheEntry struct {
	repos     []*github.Repository
	fetchedAt time.Time
}

type riskenGitHubClient struct {
	defaultToken   string
	retryer        backoff.BackOff
	logger         logging.Logger
	repoListCache  map[string]repoListCacheEntry
	repoListCacheMu sync.RWMutex
}

func NewGithubClient(defaultToken string, logger logging.Logger) *riskenGitHubClient {
	retry := RETRY_NUM
	return &riskenGitHubClient{
		defaultToken:  defaultToken,
		retryer:       backoff.WithMaxRetries(backoff.NewExponentialBackOff(), retry),
		logger:        logger,
		repoListCache: make(map[string]repoListCacheEntry),
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

func (g *riskenGitHubClient) repoListCacheKey(config *code.GitHubSetting) string {
	token := getToken(config.PersonalAccessToken, g.defaultToken)
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])[:16] // First 16 chars for uniqueness without exposing full hash
	return fmt.Sprintf("%s|%s|%s|%s", config.Type.String(), config.TargetResource, config.BaseUrl, tokenHash)
}

func (g *riskenGitHubClient) ListRepository(ctx context.Context, config *code.GitHubSetting, repoName string) ([]*github.Repository, error) {
	// For single repository scan: check cache first to skip client creation on cache hit
	if repoName != "" {
		if repo := g.getRepoFromCache(config, repoName); repo != nil {
			g.logger.Infof(ctx, "Repository %s found in cache, skipped GitHub API call", repoName)
			return []*github.Repository{repo}, nil
		}
	}

	client, err := g.newV3Client(ctx, config.PersonalAccessToken, config.BaseUrl)
	if err != nil {
		return nil, fmt.Errorf("create github-v3 client: %w", err)
	}

	if repoName != "" {
		// Cache miss: fetch full list once, cache it, then return the requested repo
		repos, err := g.getFullRepositoryList(ctx, client, config)
		if err != nil {
			return nil, err
		}
		g.setRepoListCache(config, repos)
		for _, r := range repos {
			if r.FullName != nil && *r.FullName == repoName {
				return []*github.Repository{g.copyRepository(r)}, nil
			}
		}
		// Fallback: Repositories.Get for fine-grained PATs where list may not return all accessible repos
		repo, err := g.getSingleRepositoryDirect(ctx, client, config, repoName)
		if err != nil {
			return nil, err
		}
		return []*github.Repository{repo}, nil
	}

	// Handle bulk repository scan based on config.Type
	repos, err := g.getFullRepositoryList(ctx, client, config)
	if err != nil {
		return nil, err
	}
	g.setRepoListCache(config, repos)
	return repos, nil
}

func (g *riskenGitHubClient) getRepoFromCache(config *code.GitHubSetting, repoName string) *github.Repository {
	key := g.repoListCacheKey(config)
	g.repoListCacheMu.RLock()
	defer g.repoListCacheMu.RUnlock()
	entry, ok := g.repoListCache[key]
	if !ok || time.Since(entry.fetchedAt) > repoListCacheTTL {
		return nil
	}
	for _, r := range entry.repos {
		if r.FullName != nil && *r.FullName == repoName {
			// Return a deep copy so callers don't share the same *github.Repository with other goroutines.
			// The client is shared across SQS message handlers; returning the cache pointer would cause data races if a caller mutates the object.
			return g.copyRepository(r)
		}
	}
	return nil
}

// copyRepository returns a deep copy of *github.Repository to avoid data races:
// the client is shared by multiple goroutines (SQS handlers), so returning the cache pointer would let one caller's mutations affect others.
func (g *riskenGitHubClient) copyRepository(repo *github.Repository) *github.Repository {
	if repo == nil {
		return nil
	}
	repoCopy := *repo
	// Copy pointer fields
	if repo.FullName != nil {
		fullName := *repo.FullName
		repoCopy.FullName = &fullName
	}
	if repo.Name != nil {
		name := *repo.Name
		repoCopy.Name = &name
	}
	if repo.CloneURL != nil {
		cloneURL := *repo.CloneURL
		repoCopy.CloneURL = &cloneURL
	}
	if repo.Owner != nil {
		ownerCopy := *repo.Owner
		if repo.Owner.Login != nil {
			login := *repo.Owner.Login
			ownerCopy.Login = &login
		}
		repoCopy.Owner = &ownerCopy
	}
	return &repoCopy
}

func (g *riskenGitHubClient) copyRepositoryList(repos []*github.Repository) []*github.Repository {
	if len(repos) == 0 {
		return nil
	}
	repoCopies := make([]*github.Repository, 0, len(repos))
	for _, repo := range repos {
		repoCopies = append(repoCopies, g.copyRepository(repo))
	}
	return repoCopies
}

func (g *riskenGitHubClient) setRepoListCache(config *code.GitHubSetting, repos []*github.Repository) {
	key := g.repoListCacheKey(config)
	g.repoListCacheMu.Lock()
	defer g.repoListCacheMu.Unlock()
	// Evict expired entries to prevent unbounded memory growth
	for k, entry := range g.repoListCache {
		if time.Since(entry.fetchedAt) > repoListCacheTTL {
			delete(g.repoListCache, k)
		}
	}
	// Cache isolated copies so callers cannot mutate cached repository objects.
	g.repoListCache[key] = repoListCacheEntry{repos: g.copyRepositoryList(repos), fetchedAt: time.Now()}
}

func (g *riskenGitHubClient) getSingleRepositoryDirect(ctx context.Context, client *GitHubV3Client, config *code.GitHubSetting, repoName string) (*github.Repository, error) {
	parts := strings.Split(repoName, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository name format: %s, expected 'owner/repo'", repoName)
	}
	owner, repo := parts[0], parts[1]
	if owner != config.TargetResource {
		return nil, fmt.Errorf("repository %s does not belong to %s %s", repoName, config.Type.String(), config.TargetResource)
	}
	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository %s: %w", repoName, err)
	}
	return repository, nil
}

func (g *riskenGitHubClient) getFullRepositoryList(ctx context.Context, client *GitHubV3Client, config *code.GitHubSetting) ([]*github.Repository, error) {
	switch config.Type {
	case code.Type_ORGANIZATION:
		return g.listRepositoryForOrg(ctx, client.Repositories, config)
	case code.Type_USER:
		user, _, err := client.Users.Get(ctx, "")
		if err != nil {
			return nil, err
		}
		isAuthUser := user.Login != nil && *user.Login == config.TargetResource
		return g.listRepositoryForUser(ctx, client.Repositories, config, isAuthUser)
	default:
		return nil, fmt.Errorf("unknown github type: type=%s", config.Type.String())
	}
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
		g.logger.Infof(ctx, "Success GitHub API for user repos, login:%s, option:%+v, repo_count: %d, response:%+v", login, opt, len(repos), resp)

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

func (t *riskenGitHubClient) newRetryLogger(ctx context.Context, funcName string) func(error, time.Duration) {
	return func(err error, ti time.Duration) {
		t.logger.Warnf(ctx, "[RetryLogger] %s error: duration=%+v, err=%+v", funcName, ti, err)
	}
}
