package common

import (
	"crypto/aes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/ca-risken/datasource-api/proto/code"
	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/google/go-github/v44/github"
)

func TestFilterByNamePattern(t *testing.T) {
	type args struct {
		repos   []*github.Repository
		pattern string
	}
	tests := []struct {
		name string
		args args
		want []*github.Repository
	}{
		{
			name: "Return repositories contained risken in repository name",
			args: args{
				repos: []*github.Repository{
					{
						Name: github.String("risken-core"),
					},
					{
						Name: github.String("core"),
					},
				},
				pattern: "risken",
			},
			want: []*github.Repository{
				{
					Name: github.String("risken-core"),
				},
			},
		},
		{
			name: "Return all repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name: github.String("risken-core"),
					},
					{
						Name: github.String("core"),
					},
				},
				pattern: "",
			},
			want: []*github.Repository{
				{
					Name: github.String("risken-core"),
				},
				{
					Name: github.String("core"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterByNamePattern(tt.args.repos, tt.args.pattern); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterByNamePattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterByVisibility(t *testing.T) {
	visibilityPublic := "public"
	visibilityInternal := "internal"
	visibilityPrivate := "private"
	type args struct {
		repos        []*github.Repository
		scanPublic   bool
		scanInternal bool
		scanPrivate  bool
	}
	tests := []struct {
		name string
		args args
		want []*github.Repository
	}{
		{
			name: "Return public repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanPublic: true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("public-repo"),
					Visibility: &visibilityPublic,
				},
			},
		},
		{
			name: "Return internal repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanInternal: true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("internal-repo"),
					Visibility: &visibilityInternal,
				},
			},
		},
		{
			name: "Return private repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanPrivate: true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("private-repo"),
					Visibility: &visibilityPrivate,
				},
			},
		},
		{
			name: "Return all repositories",
			args: args{
				repos: []*github.Repository{
					{
						Name:       github.String("public-repo"),
						Visibility: &visibilityPublic,
					},
					{
						Name:       github.String("internal-repo"),
						Visibility: &visibilityInternal,
					},
					{
						Name:       github.String("private-repo"),
						Visibility: &visibilityPrivate,
					},
				},
				scanPublic:   true,
				scanInternal: true,
				scanPrivate:  true,
			},
			want: []*github.Repository{
				{
					Name:       github.String("public-repo"),
					Visibility: &visibilityPublic,
				},
				{
					Name:       github.String("internal-repo"),
					Visibility: &visibilityInternal,
				},
				{
					Name:       github.String("private-repo"),
					Visibility: &visibilityPrivate,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FilterByVisibility(tt.args.repos, tt.args.scanPublic, tt.args.scanInternal, tt.args.scanPrivate); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterByRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCutString(t *testing.T) {
	type args struct {
		input string
		cut   int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Short string, no cut needed",
			args: args{
				input: "Hello",
				cut:   10,
			},
			want: "Hello",
		},
		{
			name: "Exact cut length",
			args: args{
				input: "Hello, World!",
				cut:   5,
			},
			want: "Hello ...",
		},
		{
			name: "Long string, cut applied",
			args: args{
				input: "This is a long string that needs to be cut",
				cut:   10,
			},
			want: "This is a  ...",
		},
		{
			name: "Empty string",
			args: args{
				input: "",
				cut:   5,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CutString(tt.args.input, tt.args.cut); got != tt.want {
				t.Errorf("CutString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateCloneDir(t *testing.T) {
	type args struct {
		repoName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid repo name",
			args: args{
				repoName: "testRepo",
			},
			wantErr: false,
		},
		{
			name: "Empty repo name",
			args: args{
				repoName: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := CreateCloneDir(tt.args.repoName)
			if err == nil && tt.wantErr {
				t.Errorf("CreateCloneDir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !tt.wantErr {
				t.Errorf("CreateCloneDir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				os.RemoveAll(dir)
			}
		})
	}
}

func TestDecryptGitHubPersonalAccessToken(t *testing.T) {
	block, err := aes.NewCipher([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		gitHubSetting *code.GitHubSetting
		want          string
		wantErr       bool
	}{
		{
			name: "nil setting returns empty token",
			want: "",
		},
		{
			name: "github app mode ignores personal access token",
			gitHubSetting: &code.GitHubSetting{
				AuthMode:            code.GitHubAuthModeGitHubApp,
				PersonalAccessToken: "encrypted-token",
			},
			want: "",
		},
		{
			name: "empty personal access token returns empty token",
			gitHubSetting: &code.GitHubSetting{
				AuthMode: code.GitHubAuthModePersonalAccessToken,
			},
			want: "",
		},
		{
			name: "invalid encrypted token returns error",
			gitHubSetting: &code.GitHubSetting{
				AuthMode:            code.GitHubAuthModePersonalAccessToken,
				PersonalAccessToken: "not base64",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecryptGitHubPersonalAccessToken(&block, tt.gitHubSetting)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsRetryableGitHubAppRepositoryNotFound(t *testing.T) {
	tests := []struct {
		name            string
		gitHubSetting   *code.GitHubSetting
		err             error
		wantIsRetryable bool
	}{
		{
			name:            "GitHub App go-git repository not found",
			gitHubSetting:   &code.GitHubSetting{AuthMode: code.GitHubAuthModeGitHubApp},
			err:             fmt.Errorf("failed to clone: %w", gittransport.ErrRepositoryNotFound),
			wantIsRetryable: true,
		},
		{
			name:          "PAT repository not found",
			gitHubSetting: &code.GitHubSetting{AuthMode: code.GitHubAuthModePersonalAccessToken},
			err:           errors.New("repository not found"),
		},
		{
			name:          "GitHub App other error",
			gitHubSetting: &code.GitHubSetting{AuthMode: code.GitHubAuthModeGitHubApp},
			err:           errors.New("response mentioned repository not found"),
		},
		{
			name:          "nil error",
			gitHubSetting: &code.GitHubSetting{AuthMode: code.GitHubAuthModeGitHubApp},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryableGitHubAppRepositoryNotFound(tt.gitHubSetting, tt.err); got != tt.wantIsRetryable {
				t.Fatalf("IsRetryableGitHubAppRepositoryNotFound() = %v, want %v", got, tt.wantIsRetryable)
			}
		})
	}
}

func TestGetApproximateReceiveCount(t *testing.T) {
	tests := []struct {
		name       string
		attributes map[string]string
		want       int
	}{
		{name: "valid count", attributes: map[string]string{"ApproximateReceiveCount": "2"}, want: 2},
		{name: "missing count", attributes: map[string]string{}, want: 1},
		{name: "invalid count", attributes: map[string]string{"ApproximateReceiveCount": "invalid"}, want: 1},
		{name: "non-positive count", attributes: map[string]string{"ApproximateReceiveCount": "0"}, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetApproximateReceiveCount(tt.attributes); got != tt.want {
				t.Fatalf("GetApproximateReceiveCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestShouldUpdateRepositoryStatusInProgress(t *testing.T) {
	tests := []struct {
		name         string
		receiveCount int
		want         bool
	}{
		{name: "initial delivery is already initialized", receiveCount: 1, want: false},
		{name: "second delivery restores in progress", receiveCount: 2, want: true},
		{name: "third delivery restores in progress", receiveCount: 3, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldUpdateRepositoryStatusInProgress(tt.receiveCount); got != tt.want {
				t.Fatalf("ShouldUpdateRepositoryStatusInProgress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldRetryGitHubAppRepositoryNotFound(t *testing.T) {
	gitHubAppSetting := &code.GitHubSetting{AuthMode: code.GitHubAuthModeGitHubApp}
	repositoryNotFound := fmt.Errorf("failed to clone: %w", gittransport.ErrRepositoryNotFound)
	tests := []struct {
		name         string
		setting      *code.GitHubSetting
		err          error
		receiveCount int
		want         bool
	}{
		{name: "first receive retries", setting: gitHubAppSetting, err: repositoryNotFound, receiveCount: 1, want: true},
		{name: "second receive retries", setting: gitHubAppSetting, err: repositoryNotFound, receiveCount: 2, want: true},
		{name: "third receive stops", setting: gitHubAppSetting, err: repositoryNotFound, receiveCount: 3, want: false},
		{name: "PAT does not retry", setting: &code.GitHubSetting{AuthMode: code.GitHubAuthModePersonalAccessToken}, err: repositoryNotFound, receiveCount: 1, want: false},
		{name: "other error does not retry", setting: gitHubAppSetting, err: errors.New("temporary error"), receiveCount: 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldRetryGitHubAppRepositoryNotFound(tt.setting, tt.err, tt.receiveCount); got != tt.want {
				t.Fatalf("ShouldRetryGitHubAppRepositoryNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}
