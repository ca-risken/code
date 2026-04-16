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
	name := strings.TrimSpace(repoMeta.Name)
	fullName := strings.TrimSpace(repoMeta.FullName)
	cloneURL := strings.TrimSpace(repoMeta.CloneURL)
	visibility := strings.TrimSpace(repoMeta.Visibility)
	htmlURL := strings.TrimSpace(repoMeta.HTMLURL)
	if fullName == "" || cloneURL == "" {
		return nil
	}
	size := int(repoMeta.Size)
	repo := &github.Repository{
		ID:         github.Int64(repoMeta.ID),
		Name:       github.String(name),
		FullName:   github.String(fullName),
		CloneURL:   github.String(cloneURL),
		Visibility: github.String(visibility),
		Archived:   github.Bool(repoMeta.Archived),
		Fork:       github.Bool(repoMeta.Fork),
		Disabled:   github.Bool(repoMeta.Disabled),
		Size:       &size,
		HTMLURL:    github.String(htmlURL),
	}
	if repoMeta.CreatedAt != 0 {
		repo.CreatedAt = &github.Timestamp{Time: time.Unix(repoMeta.CreatedAt, 0)}
	}
	if repoMeta.PushedAt != 0 {
		repo.PushedAt = &github.Timestamp{Time: time.Unix(repoMeta.PushedAt, 0)}
	}
	return []*github.Repository{repo}
}
