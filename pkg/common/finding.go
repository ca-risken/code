package common

import (
	"strings"

	"github.com/ca-risken/core/proto/finding"
)

const ProviderGitHub = "github"

func SetGitHubProvider(f *finding.FindingForUpsert, repositoryFullName, repositoryName string) {
	providerTarget := githubOrganization(repositoryFullName)
	if providerTarget == "" {
		providerTarget = githubOrganization(repositoryName)
	}
	f.Provider = ProviderGitHub
	f.ProviderTarget = providerTarget
}

func githubOrganization(repository string) string {
	organization, _, found := strings.Cut(strings.TrimSpace(repository), "/")
	if !found {
		return ""
	}
	return strings.TrimSpace(organization)
}
