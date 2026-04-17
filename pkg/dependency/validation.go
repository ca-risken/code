package dependency

import (
	"fmt"

	"github.com/ca-risken/code/pkg/common"
	"github.com/google/go-github/v44/github"
)

func validateRepositoryForDependency(repo *github.Repository, githubBaseURL string) error {
	if err := common.ValidateRepositoryBasic(repo, githubBaseURL); err != nil {
		return err
	}
	if repo.GetID() <= 0 {
		return fmt.Errorf("invalid repository metadata: repository id must be > 0, repository_id=%d", repo.GetID())
	}
	return nil
}
