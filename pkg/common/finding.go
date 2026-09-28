package common

import "strings"

func GetGitHubOrganization(repository string) string {
	organization, _, found := strings.Cut(strings.TrimSpace(repository), "/")
	if !found {
		return ""
	}
	return strings.TrimSpace(organization)
}
