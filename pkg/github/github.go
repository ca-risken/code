package github

import (
	"context"
	"fmt"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/cenkalti/backoff/v4"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

const RETRY_NUM uint64 = 3

type GithubServiceClient interface {
	Clone(ctx context.Context, token string, cloneURL string, dstDir string) error
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

func (t *riskenGitHubClient) newRetryLogger(ctx context.Context, funcName string) func(error, time.Duration) {
	return func(err error, ti time.Duration) {
		t.logger.Warnf(ctx, "[RetryLogger] %s error: duration=%+v, err=%+v", funcName, ti, err)
	}
}
