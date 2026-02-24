package gitleaks

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-github/v44/github"
)

func validateRepository(repo *github.Repository, githubBaseURL string) error {
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
	if err := validateCloneURL(repo.GetCloneURL(), repo.GetFullName(), githubBaseURL); err != nil {
		return err
	}
	if err := validateHTMLURL(repo.GetHTMLURL(), repo.GetFullName(), githubBaseURL); err != nil {
		return err
	}
	return nil
}

func validateCloneURL(cloneURL, repoFullName, githubBaseURL string) error {
	u, err := url.Parse(cloneURL)
	if err != nil {
		return fmt.Errorf("invalid repository metadata: clone_url parse error: clone_url=%s, err=%w", cloneURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("invalid repository metadata: clone_url scheme must be https: clone_url=%s", cloneURL)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid repository metadata: clone_url host is required: clone_url=%s", cloneURL)
	}

	allowedHosts := allowedCloneHosts(githubBaseURL)
	if _, ok := allowedHosts[strings.ToLower(u.Hostname())]; !ok {
		return fmt.Errorf("invalid repository metadata: clone_url host is not allowed: clone_url=%s, allowed_hosts=%v", cloneURL, keys(allowedHosts))
	}

	normalizedPath := strings.TrimPrefix(u.EscapedPath(), "/")
	normalizedPath = strings.TrimSuffix(normalizedPath, ".git")
	if normalizedPath != repoFullName {
		return fmt.Errorf("invalid repository metadata: clone_url path does not match repository full_name: clone_url=%s, repository_full_name=%s", cloneURL, repoFullName)
	}
	return nil
}

func validateHTMLURL(htmlURL, repoFullName, githubBaseURL string) error {
	u, err := url.Parse(htmlURL)
	if err != nil {
		return fmt.Errorf("invalid repository metadata: html_url parse error: html_url=%s, err=%w", htmlURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("invalid repository metadata: html_url scheme must be https: html_url=%s", htmlURL)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid repository metadata: html_url host is required: html_url=%s", htmlURL)
	}

	allowedHosts := allowedCloneHosts(githubBaseURL)
	if _, ok := allowedHosts[strings.ToLower(u.Hostname())]; !ok {
		return fmt.Errorf("invalid repository metadata: html_url host is not allowed: html_url=%s, allowed_hosts=%v", htmlURL, keys(allowedHosts))
	}

	normalizedPath := strings.TrimPrefix(u.EscapedPath(), "/")
	if normalizedPath != repoFullName {
		return fmt.Errorf("invalid repository metadata: html_url path does not match repository full_name: html_url=%s, repository_full_name=%s", htmlURL, repoFullName)
	}
	return nil
}

func allowedCloneHosts(githubBaseURL string) map[string]struct{} {
	if githubBaseURL == "" {
		return map[string]struct{}{"github.com": {}}
	}
	hosts := make(map[string]struct{})
	u, err := url.Parse(githubBaseURL)
	if err != nil || u.Hostname() == "" {
		return hosts
	}
	host := strings.ToLower(u.Hostname())
	hosts[host] = struct{}{}
	if strings.HasPrefix(host, "api.") {
		hosts[strings.TrimPrefix(host, "api.")] = struct{}{}
	}
	return hosts
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
