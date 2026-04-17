package gitleaks

import (
	"fmt"
	"strings"

	"github.com/ca-risken/code/pkg/common"
	"github.com/google/go-github/v44/github"
)

func validateRepositoryForGitleaks(repo *github.Repository, githubBaseURL string) error {
	if err := common.ValidateRepositoryBasic(repo, githubBaseURL); err != nil {
		return err
	}

	fullName := strings.TrimSpace(repo.GetFullName())
	if repo.Visibility == nil || strings.TrimSpace(repo.GetVisibility()) == "" {
		return fmt.Errorf("invalid repository metadata: visibility is required, repository=%s", fullName)
	}
	if repo.CreatedAt == nil {
		return fmt.Errorf("invalid repository metadata: queue message repository.created_at is required (>0 unix time), repository=%s", fullName)
	}
	if repo.CreatedAt.Unix() <= 0 {
		return fmt.Errorf("invalid repository metadata: queue message repository.created_at must be >0 unix time, repository=%s, created_at=%d", fullName, repo.CreatedAt.Unix())
	}
	if repo.PushedAt == nil {
		return fmt.Errorf("invalid repository metadata: queue message repository.pushed_at is required (>0 unix time), repository=%s", fullName)
	}
	if repo.PushedAt.Unix() <= 0 {
		return fmt.Errorf("invalid repository metadata: queue message repository.pushed_at must be >0 unix time, repository=%s, pushed_at=%d", fullName, repo.PushedAt.Unix())
	}
	return nil
}
