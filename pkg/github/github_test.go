package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/proto/code"
)

var defaultTransportMu sync.Mutex

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

func useTestGitHubAppTransport(t *testing.T, server *httptest.Server) {
	t.Helper()
	defaultTransportMu.Lock()
	origTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() {
		http.DefaultTransport = origTransport
		defaultTransportMu.Unlock()
	})
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

func TestResolveInstallationToken(t *testing.T) {
	privateKeyPEM := generateRSAPrivateKeyPEM(t)
	var handlerState struct {
		mu               sync.Mutex
		err              error
		gotAuthorization string
		gotRepositories  []string
	}
	recordHandlerError := func(format string, args ...any) {
		handlerState.mu.Lock()
		defer handlerState.mu.Unlock()
		if handlerState.err == nil {
			handlerState.err = fmt.Errorf(format, args...)
		}
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/12345/access_tokens" {
			recordHandlerError("unexpected path: %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPost {
			recordHandlerError("unexpected method: %s", r.Method)
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		handlerState.mu.Lock()
		handlerState.gotAuthorization = r.Header.Get("Authorization")
		handlerState.mu.Unlock()

		var body struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			recordHandlerError("decode request body: %v", err)
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		handlerState.mu.Lock()
		handlerState.gotRepositories = body.Repositories
		handlerState.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"token":"installation-token"}`)); err != nil {
			recordHandlerError("write response: %v", err)
			return
		}
	}))
	defer server.Close()
	useTestGitHubAppTransport(t, server)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	client, err := NewGithubClientWithAppAuth("default-token", &AppAuthConfig{
		AppID:               "12345",
		PrivateKey:          privateKeyPEM,
		AllowedBaseURLHosts: []string{serverURL.Hostname()},
	}, logging.NewLogger())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	got, err := client.ResolveInstallationToken(context.Background(), &code.GitHubSetting{
		BaseUrl:        server.URL + "/",
		InstallationId: 12345,
	}, "owner/repo")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	handlerState.mu.Lock()
	handlerErr := handlerState.err
	gotAuthorization := handlerState.gotAuthorization
	gotRepositories := handlerState.gotRepositories
	handlerState.mu.Unlock()
	if handlerErr != nil {
		t.Fatalf("handler error: %v", handlerErr)
	}
	if got != "installation-token" {
		t.Fatalf("Unexpected token: %s", got)
	}
	if !strings.HasPrefix(gotAuthorization, "Bearer ") {
		t.Fatalf("Unexpected authorization header: %s", gotAuthorization)
	}
	if len(gotRepositories) != 1 || gotRepositories[0] != "repo" {
		t.Fatalf("Unexpected repositories: %+v", gotRepositories)
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
		name   string
		client *riskenGitHubClient
		config *code.GitHubSetting
		repo   string
	}{
		{
			name:   "app auth not configured",
			client: NewGithubClient("default-token", logging.NewLogger()),
			config: &code.GitHubSetting{InstallationId: 12345},
		},
		{
			name:   "empty repo name",
			client: clientWithAppAuth,
			config: &code.GitHubSetting{InstallationId: 12345},
		},
		{
			name:   "whitespace repo name",
			client: clientWithAppAuth,
			config: &code.GitHubSetting{InstallationId: 12345},
			repo:   " ",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.client.ResolveInstallationToken(context.Background(), c.config, c.repo); err == nil {
				t.Fatal("Expected error but got none")
			}
		})
	}
}
