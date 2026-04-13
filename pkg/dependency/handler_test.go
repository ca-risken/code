package dependency

import (
	"testing"

	"github.com/ca-risken/datasource-api/pkg/message"
)

func TestGetRepositoriesFromCodeQueueMessage(t *testing.T) {
	t.Run("Repository metadata exists", func(t *testing.T) {
		msg := &message.CodeQueueMessage{
			Repository: &message.RepositoryMetadata{
				Name:       "repo",
				FullName:   "owner/repo",
				CloneURL:   "https://github.com/owner/repo.git",
				Visibility: "private",
				Archived:   false,
				Fork:       false,
				Disabled:   false,
				Size:       123,
				HTMLURL:    "https://github.com/owner/repo",
			},
		}
		repos := getRepositoriesFromCodeQueueMessage(msg)
		if len(repos) != 1 {
			t.Fatalf("unexpected repository count: %+v", len(repos))
		}
		if repos[0].GetFullName() != "owner/repo" {
			t.Fatalf("unexpected full_name: %+v", repos[0].GetFullName())
		}
		if repos[0].GetCloneURL() != "https://github.com/owner/repo.git" {
			t.Fatalf("unexpected clone_url: %+v", repos[0].GetCloneURL())
		}
	})

	t.Run("Repository metadata is nil", func(t *testing.T) {
		repos := getRepositoriesFromCodeQueueMessage(&message.CodeQueueMessage{})
		if len(repos) != 0 {
			t.Fatalf("unexpected repository count: %+v", len(repos))
		}
	})
}
