package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
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
