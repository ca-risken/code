package gitleaks

import (
	"fmt"

	"github.com/google/go-github/v44/github"
)

func validateRepositoriesForFilter(repos []*github.Repository) error {
	for _, r := range repos {
		if r == nil {
			return fmt.Errorf("invalid repository metadata: repository is nil")
		}
		if r.Name == nil || *r.Name == "" {
			return fmt.Errorf("invalid repository metadata: name is required")
		}
		if r.FullName == nil || *r.FullName == "" {
			return fmt.Errorf("invalid repository metadata: full_name is required")
		}
		if r.Visibility == nil || *r.Visibility == "" {
			return fmt.Errorf("invalid repository metadata: visibility is required, repository=%s", r.GetFullName())
		}
	}
	return nil
}

func validateRepositoryForScan(repo *github.Repository) error {
	if repo == nil {
		return fmt.Errorf("invalid repository metadata: repository is nil")
	}
	if repo.CloneURL == nil || *repo.CloneURL == "" {
		return fmt.Errorf("invalid repository metadata: clone_url is required, repository=%s", repo.GetFullName())
	}
	if repo.CreatedAt == nil {
		return fmt.Errorf("invalid repository metadata: created_at is required, repository=%s", repo.GetFullName())
	}
	if repo.PushedAt == nil {
		return fmt.Errorf("invalid repository metadata: pushed_at is required, repository=%s", repo.GetFullName())
	}
	if repo.HTMLURL == nil || *repo.HTMLURL == "" {
		return fmt.Errorf("invalid repository metadata: html_url is required, repository=%s", repo.GetFullName())
	}
	return nil
}
