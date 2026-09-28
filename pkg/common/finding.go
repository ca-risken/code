package common

import (
	"strings"

	"github.com/ca-risken/core/proto/finding"
)

const ProviderGitHub = "github"

func SetGitHubProvider(f *finding.FindingForUpsert, repositoryFullName, repositoryName string) {
	providerTarget := strings.TrimSpace(repositoryFullName)
	if providerTarget == "" {
		providerTarget = strings.TrimSpace(repositoryName)
	}
	f.Provider = ProviderGitHub
	f.ProviderTarget = providerTarget
}
