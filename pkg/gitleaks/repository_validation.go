package gitleaks

import (
	"fmt"

	"github.com/google/go-github/v44/github"
)

func validateRepository(repo *github.Repository) error {
	if repo == nil {
		return fmt.Errorf("invalid repository metadata: repository is nil")
	}
	if repo.Name == nil || *repo.Name == "" {
		return fmt.Errorf("invalid repository metadata: name is required")
	}
	if repo.FullName == nil || *repo.FullName == "" {
		return fmt.Errorf("invalid repository metadata: full_name is required")
	}
	if repo.Visibility == nil || *repo.Visibility == "" {
		return fmt.Errorf("invalid repository metadata: visibility is required, repository=%s", repo.GetFullName())
	}
	if repo.CloneURL == nil || *repo.CloneURL == "" {
		return fmt.Errorf("invalid repository metadata: clone_url is required, repository=%s", repo.GetFullName())
	}
	if repo.CreatedAt == nil {
		return fmt.Errorf("invalid repository metadata: queue message repository.created_at is required (>0 unix time), repository=%s", repo.GetFullName())
	}
	if repo.PushedAt == nil {
		return fmt.Errorf("invalid repository metadata: queue message repository.pushed_at is required (>0 unix time), repository=%s", repo.GetFullName())
	}
	if repo.HTMLURL == nil || *repo.HTMLURL == "" {
		return fmt.Errorf("invalid repository metadata: html_url is required, repository=%s", repo.GetFullName())
	}
	return nil
}
