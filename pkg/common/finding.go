package common

import "strings"

func GetGitHubOrganization(repositoryFullName, repositoryName string) string {
	organization := githubOrganization(repositoryFullName)
	if organization == "" {
		organization = githubOrganization(repositoryName)
	}
	return organization
}

func githubOrganization(repository string) string {
	organization, _, found := strings.Cut(strings.TrimSpace(repository), "/")
	if !found {
		return ""
	}
	return strings.TrimSpace(organization)
}
