package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	var gotAuthorization string
	var gotRepositories []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/12345/access_tokens" {
			t.Fatalf("Unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("Unexpected method: %s", r.Method)
		}
		gotAuthorization = r.Header.Get("Authorization")
		var body struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		gotRepositories = body.Repositories
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"token":"installation-token"}`)); err != nil {
			t.Fatalf("write response: %v", err)
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
	client := NewGithubClient("default-token", logging.NewLogger())
	if _, err := client.ResolveInstallationToken(context.Background(), &code.GitHubSetting{InstallationId: 12345}, ""); err == nil {
		t.Fatal("Expected error but got none")
	}
}
