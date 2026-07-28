package common

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	codecrypto "github.com/ca-risken/code/pkg/crypto"
	"github.com/ca-risken/datasource-api/proto/code"
	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/google/go-github/v44/github"
)

const MaxGitHubAppRepositoryNotFoundReceiveCount = 3

func FilterByNamePattern(repos []*github.Repository, pattern string) []*github.Repository {
	var filteredRepos []*github.Repository
	for _, repo := range repos {
		if strings.Contains(*repo.Name, pattern) {
			filteredRepos = append(filteredRepos, repo)
		}
	}

	return filteredRepos
}

const (
	githubVisibilityPublic   string = "public"
	githubVisibilityInternal string = "internal"
	githubVisibilityPrivate  string = "private"
)

func FilterByVisibility(repos []*github.Repository, scanPublic, scanInternal, scanPrivate bool) []*github.Repository {
	var filteredRepos []*github.Repository
	for _, repo := range repos {
		if scanPublic && *repo.Visibility == githubVisibilityPublic {
			filteredRepos = append(filteredRepos, repo)
		}
		if scanInternal && *repo.Visibility == githubVisibilityInternal {
			filteredRepos = append(filteredRepos, repo)
		}
		if scanPrivate && *repo.Visibility == githubVisibilityPrivate {
			filteredRepos = append(filteredRepos, repo)
		}
	}
	return filteredRepos
}

func CutString(input string, cut int) string {
	if len(input) > cut {
		return input[:cut] + " ..." // cut long text
	}
	return input
}

func CreateCloneDir(repoName string) (string, error) {
	if repoName == "" {
		return "", errors.New("invalid value: repoName is not empty")
	}

	dir, err := os.MkdirTemp("", repoName)
	if err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	return dir, nil
}

func DecryptGitHubPersonalAccessToken(block *cipher.Block, gitHubSetting *code.GitHubSetting) (string, error) {
	if gitHubSetting == nil || gitHubSetting.AuthMode == code.GitHubAuthModeGitHubApp || gitHubSetting.PersonalAccessToken == "" {
		return "", nil
	}
	return codecrypto.DecryptWithBase64(block, gitHubSetting.PersonalAccessToken)
}

func IsRetryableGitHubAppRepositoryNotFound(gitHubSetting *code.GitHubSetting, err error) bool {
	if gitHubSetting == nil || gitHubSetting.AuthMode != code.GitHubAuthModeGitHubApp || err == nil {
		return false
	}
	return errors.Is(err, gittransport.ErrRepositoryNotFound)
}

func GetApproximateReceiveCount(attributes map[string]string) int {
	count, err := strconv.Atoi(attributes["ApproximateReceiveCount"])
	if err != nil || count < 1 {
		return 1
	}
	return count
}

func ShouldUpdateRepositoryStatusInProgress(receiveCount int) bool {
	return receiveCount > 1
}

func ShouldRetryGitHubAppRepositoryNotFound(gitHubSetting *code.GitHubSetting, err error, receiveCount int) bool {
	return receiveCount < MaxGitHubAppRepositoryNotFoundReceiveCount &&
		IsRetryableGitHubAppRepositoryNotFound(gitHubSetting, err)
}
