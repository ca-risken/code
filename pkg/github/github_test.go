package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
)

func generateRSAPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa private key: %v", err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	return string(pem.EncodeToMemory(block))
}

func TestNewGithubClientWithAppAuth(t *testing.T) {
	privateKeyPEM := generateRSAPrivateKeyPEM(t)
	cases := []struct {
		name      string
		conf      *AppAuthConfig
		wantApp   bool
		wantError bool
	}{
		{
			name: "OK no app auth",
		},
		{
			name: "OK empty app auth",
			conf: &AppAuthConfig{},
		},
		{
			name:    "OK app auth",
			conf:    &AppAuthConfig{AppID: "12345", PrivateKey: privateKeyPEM},
			wantApp: true,
		},
		{
			name:      "NG missing private key",
			conf:      &AppAuthConfig{AppID: "12345"},
			wantError: true,
		},
		{
			name:      "NG invalid app id",
			conf:      &AppAuthConfig{AppID: "invalid", PrivateKey: privateKeyPEM},
			wantError: true,
		},
		{
			name:      "NG invalid private key",
			conf:      &AppAuthConfig{AppID: "12345", PrivateKey: "invalid"},
			wantError: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, err := NewGithubClientWithAppAuth("default-token", c.conf, logging.NewLogger())
			if c.wantError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if got := client.SupportsGitHubApp(); got != c.wantApp {
				t.Fatalf("Unexpected GitHub App support: want=%t, got=%t", c.wantApp, got)
			}
		})
	}
}

func TestResolveInstallationTokenError(t *testing.T) {
	privateKeyPEM := generateRSAPrivateKeyPEM(t)
	clientWithAppAuth, err := NewGithubClientWithAppAuth("default-token", &AppAuthConfig{
		AppID:      "12345",
		PrivateKey: privateKeyPEM,
	}, logging.NewLogger())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	cases := []struct {
		name    string
		client  *riskenGitHubClient
		config  *code.GitHubSetting
		repo    string
		wantErr string
	}{
		{
			name:    "app auth not configured",
			client:  NewGithubClient("default-token", logging.NewLogger()),
			config:  &code.GitHubSetting{InstallationId: 12345},
			repo:    "owner/repo",
			wantErr: "github app auth is not configured",
		},
		{
			name:    "nil github setting",
			client:  clientWithAppAuth,
			config:  nil,
			repo:    "owner/repo",
			wantErr: "github setting is required",
		},
		{
			name:    "missing installation id",
			client:  clientWithAppAuth,
			config:  &code.GitHubSetting{},
			repo:    "owner/repo",
			wantErr: "installation_id is required",
		},
		{
			name:    "empty repo name",
			client:  clientWithAppAuth,
			config:  &code.GitHubSetting{InstallationId: 12345},
			wantErr: "repo_name is required",
		},
		{
			name:    "whitespace repo name",
			client:  clientWithAppAuth,
			config:  &code.GitHubSetting{InstallationId: 12345},
			repo:    " ",
			wantErr: "repo_name is required",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.client.ResolveInstallationToken(context.Background(), c.config, c.repo)
			if err == nil {
				t.Fatal("Expected error but got none")
			}
			if c.wantErr != "" && err.Error() != c.wantErr {
				t.Fatalf("Unexpected error: got %q want %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestResolveAccessToken(t *testing.T) {
	client := NewGithubClient("default-token", logging.NewLogger())
	cases := []struct {
		name     string
		config   *code.GitHubSetting
		patToken string
		want     string
	}{
		{
			name:     "personal access token",
			config:   &code.GitHubSetting{AuthMode: code.GitHubAuthModePersonalAccessToken},
			patToken: "pat-token",
			want:     "pat-token",
		},
		{
			name:   "default token fallback",
			config: &code.GitHubSetting{AuthMode: code.GitHubAuthModePersonalAccessToken},
			want:   "default-token",
		},
		{
			name:     "empty auth mode keeps pat behavior",
			config:   &code.GitHubSetting{},
			patToken: "pat-token",
			want:     "pat-token",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := client.ResolveAccessToken(context.Background(), c.config, "owner/repo", c.patToken)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("Unexpected token: want=%s, got=%s", c.want, got)
			}
		})
	}
}

func TestResolveAccessTokenGitHubAppRequiresAppAuth(t *testing.T) {
	client := NewGithubClient("default-token", logging.NewLogger())
	_, err := client.ResolveAccessToken(context.Background(), &code.GitHubSetting{
		AuthMode:       code.GitHubAuthModeGitHubApp,
		InstallationId: 12345,
	}, "owner/repo", "pat-token")
	if err == nil {
		t.Fatal("Expected error but got none")
	}
	if err.Error() != "github app auth is not configured" {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestCloneRetryPolicy(t *testing.T) {
	cases := []struct {
		name        string
		ctx         context.Context
		cloneErr    error
		wantAttempt int32
	}{
		{
			name:        "GitHub App repository not found retries independently",
			ctx:         WithRepositoryNotFoundRetry(context.Background()),
			cloneErr:    gittransport.ErrRepositoryNotFound,
			wantAttempt: 4,
		},
		{
			name:        "repository not found without GitHub App retry",
			ctx:         context.Background(),
			cloneErr:    gittransport.ErrRepositoryNotFound,
			wantAttempt: 4,
		},
		{
			name:        "non retryable error",
			ctx:         WithRepositoryNotFoundRetry(context.Background()),
			cloneErr:    errors.New("permanent"),
			wantAttempt: 4,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var attempts atomic.Int32
			client := &riskenGitHubClient{
				logger: logging.NewLogger(),
				clone: func(token, cloneURL, dstDir string) error {
					attempts.Add(1)
					return c.cloneErr
				},
				wait: func(context.Context, time.Duration) error { return nil },
			}
			dir := t.TempDir()

			err := client.Clone(c.ctx, "token", "https://github.com/owner/repo.git", dir)
			if err == nil {
				t.Fatal("Clone() error = nil, want error")
			}
			if got := attempts.Load(); got != c.wantAttempt {
				t.Fatalf("Clone() attempts = %d, want %d", got, c.wantAttempt)
			}
		})
	}
}

func TestCloneRetryIsolationUnderConcurrency(t *testing.T) {
	const concurrentCalls = 10
	var attempts atomic.Int32
	client := &riskenGitHubClient{
		logger: logging.NewLogger(),
		clone: func(token, cloneURL, dstDir string) error {
			attempts.Add(1)
			return gittransport.ErrRepositoryNotFound
		},
		wait: func(context.Context, time.Duration) error { return nil },
	}

	var wg sync.WaitGroup
	wg.Add(concurrentCalls)
	for range concurrentCalls {
		go func() {
			defer wg.Done()
			err := client.Clone(
				WithRepositoryNotFoundRetry(context.Background()),
				"token",
				"https://github.com/owner/repo.git",
				t.TempDir(),
			)
			if err == nil {
				t.Errorf("Clone() error = nil, want error")
			}
		}()
	}
	wg.Wait()

	if got, want := attempts.Load(), int32(concurrentCalls*(len(gitHubAppRepositoryNotFoundRetryIntervals)+1)); got != want {
		t.Fatalf("Clone() total attempts = %d, want %d", got, want)
	}
}

func TestCloneCleansDestinationBeforeRetry(t *testing.T) {
	var attempts int
	client := &riskenGitHubClient{
		logger: logging.NewLogger(),
		clone: func(token, cloneURL, dstDir string) error {
			attempts++
			partialPath := filepath.Join(dstDir, "partial")
			if attempts == 1 {
				if err := os.WriteFile(partialPath, []byte("partial"), 0600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				return gittransport.ErrRepositoryNotFound
			}
			if _, err := os.Stat(partialPath); !os.IsNotExist(err) {
				t.Fatalf("partial clone data remains before retry: err=%v", err)
			}
			return nil
		},
		wait: func(context.Context, time.Duration) error { return nil },
	}

	if err := client.Clone(
		WithRepositoryNotFoundRetry(context.Background()),
		"token",
		"https://github.com/owner/repo.git",
		t.TempDir(),
	); err != nil {
		t.Fatalf("Clone() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("Clone() attempts = %d, want 2", attempts)
	}
}
