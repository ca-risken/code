package github

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ca-risken/common/pkg/githubappauth"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/cenkalti/backoff/v4"
	"github.com/go-git/go-git/v5"
	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

var gitHubAppRepositoryNotFoundRetryIntervals = []time.Duration{
	3 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

const RETRY_NUM uint64 = 3

type GithubServiceClient interface {
	Clone(ctx context.Context, token string, cloneURL string, dstDir string) error
	SupportsGitHubApp() bool
	ResolveAccessToken(ctx context.Context, config *code.GitHubSetting, repoName, personalAccessToken string) (string, error)
	ResolveInstallationToken(ctx context.Context, config *code.GitHubSetting, repoName string) (string, error)
}

type AppAuthConfig = githubappauth.Config
type retryRepositoryNotFoundContextKey struct{}

func WithRepositoryNotFoundRetry(ctx context.Context) context.Context {
	return context.WithValue(ctx, retryRepositoryNotFoundContextKey{}, true)
}

type riskenGitHubClient struct {
	defaultToken string
	appAuth      *githubappauth.Client
	logger       logging.Logger
	clone        func(token, cloneURL, dstDir string) error
	wait         func(context.Context, time.Duration) error
}

func NewGithubClient(defaultToken string, logger logging.Logger) *riskenGitHubClient {
	client, err := NewGithubClientWithAppAuth(defaultToken, nil, logger)
	if err != nil {
		logger.Warnf(context.Background(), "failed to initialize GitHub App auth; using PAT-only client: %+v", err)
		return &riskenGitHubClient{
			defaultToken: defaultToken,
			logger:       logger,
			clone:        cloneRepository,
			wait:         waitForRetry,
		}
	}
	return client
}

func NewGithubClientWithAppAuth(defaultToken string, appAuthCfg *AppAuthConfig, logger logging.Logger) (*riskenGitHubClient, error) {
	appAuth, err := githubappauth.NewClient(appAuthCfg)
	if err != nil {
		return nil, err
	}
	if !appAuth.Enabled() {
		appAuth = nil
	}
	return &riskenGitHubClient{
		defaultToken: defaultToken,
		appAuth:      appAuth,
		logger:       logger,
		clone:        cloneRepository,
		wait:         waitForRetry,
	}, nil
}

func getToken(token, defaultToken string) string {
	if token != "" {
		return token
	}
	return defaultToken
}

func cloneRepository(token, cloneURL, dstDir string) error {
	_, err := git.PlainClone(dstDir, false, &git.CloneOptions{
		URL: cloneURL,
		Auth: &http.BasicAuth{
			Username: "dummy", // anything except an empty string
			Password: token,
		},
	})
	return err
}

func waitForRetry(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (g *riskenGitHubClient) Clone(ctx context.Context, token string, cloneURL string, dstDir string) error {
	retryRepositoryNotFound, _ := ctx.Value(retryRepositoryNotFoundContextKey{}).(bool)
	resolvedToken := getToken(token, g.defaultToken)
	err := g.clone(resolvedToken, cloneURL, dstDir)
	if err == nil {
		return nil
	}
	return g.retryClone(ctx, resolvedToken, cloneURL, dstDir, err, retryRepositoryNotFound)
}

func (g *riskenGitHubClient) retryClone(ctx context.Context, token, cloneURL, dstDir string, initialErr error, retryRepositoryNotFound bool) error {
	err := initialErr
	retryer := backoff.NewExponentialBackOff()
	retryer.Reset()
	repositoryNotFoundRetryIndex := 0
	for range RETRY_NUM {
		var interval time.Duration
		if retryRepositoryNotFound && errors.Is(err, gittransport.ErrRepositoryNotFound) {
			if repositoryNotFoundRetryIndex >= len(gitHubAppRepositoryNotFoundRetryIntervals) {
				break
			}
			interval = gitHubAppRepositoryNotFoundRetryIntervals[repositoryNotFoundRetryIndex]
			repositoryNotFoundRetryIndex++
		} else {
			interval = retryer.NextBackOff()
			if interval == backoff.Stop {
				break
			}
		}
		g.newRetryLogger(ctx, "github clone")(err, interval)
		if waitErr := g.wait(ctx, interval); waitErr != nil {
			return fmt.Errorf("failed to clone %s to %s: %w", cloneURL, dstDir, errors.Join(err, waitErr))
		}
		if prepareErr := prepareCloneDestination(dstDir); prepareErr != nil {
			return errors.Join(err, prepareErr)
		}
		err = g.clone(token, cloneURL, dstDir)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("failed to clone %s to %s: %w", cloneURL, dstDir, err)
}

func prepareCloneDestination(dstDir string) error {
	cleanedDstDir := filepath.Clean(dstDir)
	tempDir := filepath.Clean(os.TempDir())
	relativePath, err := filepath.Rel(tempDir, cleanedDstDir)
	if err != nil || !filepath.IsAbs(cleanedDstDir) || relativePath == "." || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("unsafe clone destination: %s", dstDir)
	}
	if err := os.RemoveAll(cleanedDstDir); err != nil {
		return fmt.Errorf("failed to clean clone destination %s: %w", dstDir, err)
	}
	if err := os.MkdirAll(cleanedDstDir, 0700); err != nil {
		return fmt.Errorf("failed to recreate clone destination %s: %w", dstDir, err)
	}
	return nil
}

func (g *riskenGitHubClient) SupportsGitHubApp() bool {
	return g.appAuth != nil && g.appAuth.Enabled()
}

func (g *riskenGitHubClient) ResolveAccessToken(ctx context.Context, config *code.GitHubSetting, repoName, personalAccessToken string) (string, error) {
	if config != nil && config.AuthMode == code.GitHubAuthModeGitHubApp {
		return g.ResolveInstallationToken(ctx, config, repoName)
	}
	return getToken(personalAccessToken, g.defaultToken), nil
}

func (g *riskenGitHubClient) ResolveInstallationToken(ctx context.Context, config *code.GitHubSetting, repoName string) (string, error) {
	if g.appAuth == nil {
		return "", errors.New("github app auth is not configured")
	}
	if config == nil {
		return "", errors.New("github setting is required")
	}
	if config.InstallationId == 0 {
		return "", errors.New("installation_id is required")
	}
	if strings.TrimSpace(repoName) == "" {
		return "", errors.New("repo_name is required")
	}
	return g.appAuth.ResolveInstallationToken(ctx, &githubappauth.InstallationTokenConfig{
		BaseURL:        config.BaseUrl,
		InstallationID: config.InstallationId,
	}, repoName)
}

func (t *riskenGitHubClient) newRetryLogger(ctx context.Context, funcName string) func(error, time.Duration) {
	return func(err error, ti time.Duration) {
		t.logger.Warnf(ctx, "[RetryLogger] %s error: duration=%+v, err=%+v", funcName, ti, err)
	}
}
