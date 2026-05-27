package github

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ca-risken/common/pkg/githubappauth"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/cenkalti/backoff/v4"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

const RETRY_NUM uint64 = 3

type GithubServiceClient interface {
	Clone(ctx context.Context, token string, cloneURL string, dstDir string) error
	SupportsGitHubApp() bool
	ResolveInstallationToken(ctx context.Context, config *code.GitHubSetting, repoName string) (string, error)
}

// AppAuthConfig is the server-side GitHub App credential set.
type AppAuthConfig = githubappauth.Config

type riskenGitHubClient struct {
	defaultToken string
	appAuth      *githubappauth.Client
	retryer      backoff.BackOff
	logger       logging.Logger
}

func NewGithubClient(defaultToken string, logger logging.Logger) *riskenGitHubClient {
	// githubappauth.NewClient(nil) does not return an error today; keep PAT-only behavior if that changes.
	client, err := NewGithubClientWithAppAuth(defaultToken, nil, logger)
	if err != nil {
		logger.Warnf(context.Background(), "failed to initialize GitHub App auth; using PAT-only client: %+v", err)
		retry := RETRY_NUM
		return &riskenGitHubClient{
			defaultToken: defaultToken,
			retryer:      backoff.WithMaxRetries(backoff.NewExponentialBackOff(), retry),
			logger:       logger,
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
	retry := RETRY_NUM
	return &riskenGitHubClient{
		defaultToken: defaultToken,
		appAuth:      appAuth,
		retryer:      backoff.WithMaxRetries(backoff.NewExponentialBackOff(), retry),
		logger:       logger,
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

func (g *riskenGitHubClient) SupportsGitHubApp() bool {
	return g.appAuth != nil && g.appAuth.Enabled()
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
