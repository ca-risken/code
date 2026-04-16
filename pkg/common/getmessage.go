package common

import (
	"strings"
	"time"

	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/google/go-github/v44/github"
)

// GetRepositoriesFromCodeQueueMessage builds go-github Repository values from queue message metadata.
func GetRepositoriesFromCodeQueueMessage(msg *message.CodeQueueMessage) []*github.Repository {
	if msg == nil || msg.Repository == nil {
		return nil
	}
	repoMeta := msg.Repository
	if strings.TrimSpace(repoMeta.FullName) == "" || strings.TrimSpace(repoMeta.CloneURL) == "" {
		return nil
	}
	size := int(repoMeta.Size)
	repo := &github.Repository{
		ID:         github.Int64(repoMeta.ID),
		Name:       github.String(repoMeta.Name),
		FullName:   github.String(repoMeta.FullName),
		CloneURL:   github.String(repoMeta.CloneURL),
		Visibility: github.String(repoMeta.Visibility),
		Archived:   github.Bool(repoMeta.Archived),
		Fork:       github.Bool(repoMeta.Fork),
		Disabled:   github.Bool(repoMeta.Disabled),
		Size:       &size,
		HTMLURL:    github.String(repoMeta.HTMLURL),
	}
	if repoMeta.CreatedAt != 0 {
		repo.CreatedAt = &github.Timestamp{Time: time.Unix(repoMeta.CreatedAt, 0)}
	}
	if repoMeta.PushedAt != 0 {
		repo.PushedAt = &github.Timestamp{Time: time.Unix(repoMeta.PushedAt, 0)}
	}
	return []*github.Repository{repo}
}
