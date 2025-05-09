package common

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-github/v44/github"
)

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
