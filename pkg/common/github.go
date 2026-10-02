package common

import "strings"

func GetGitHubOwner(repository string) string {
	owner, _, found := strings.Cut(strings.TrimSpace(repository), "/")
	if !found {
		return ""
	}
	return strings.TrimSpace(owner)
}
