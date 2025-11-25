package codescan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ca-risken/code/pkg/common"
	"github.com/ca-risken/datasource-api/proto/code"
)

func (s *sqsHandler) scanForRepository(ctx context.Context, r *code.GitHubRepository, token, githubBaseURL string) ([]*SemgrepFinding, error) {
	// Extract repository name from full name (e.g., "owner/repo" -> "repo")
	repoName := r.FullName
	if parts := strings.Split(r.FullName, "/"); len(parts) > 0 {
		repoName = parts[len(parts)-1]
	}

	if r.DefaultBranch == "" {
		return nil, fmt.Errorf("default branch is not set for repository: repo=%s", r.FullName)
	}
	defaultBranch := r.DefaultBranch
	// Clone repository
	dir, err := common.CreateCloneDir(repoName)
	if err != nil {
		return nil, fmt.Errorf("failed to create directory to clone: repo=%s err=%w", r.FullName, err)
	}
	defer os.RemoveAll(dir)

	err = s.githubClient.Clone(ctx, token, r.CloneUrl, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to clone: repo=%s err=%w", r.FullName, err)
	}

	// Scemgrep
	findings, err := s.semgrepScan(ctx, dir, r.FullName, defaultBranch, githubBaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to scan: repo=%s  err=%w", r.FullName, err)
	}
	return findings, nil
}

func (s *sqsHandler) semgrepScan(ctx context.Context, targetDir, repository, defaultBranch, githubBaseURL string) ([]*SemgrepFinding, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx,
		"semgrep",
		"scan",
		"--config=p/default",
		"--json",
		targetDir,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	s.logger.Infof(ctx, "Start semgrep scan start: repository=%s", repository)

	err := cmd.Run()
	if err != nil {
		s.logger.Errorf(ctx, "Failed semgrep scan: repository=%s", repository)
		return nil, fmt.Errorf("failed to execute semgrep: targetDir=%s, err=%w, stderr=%+v", targetDir, err, stderr.String())
	}
	findings, err := ParseSemgrepResult(targetDir, stdout.String(), repository, defaultBranch, githubBaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep: targetDir=%s, err=%w", targetDir, err)
	}
	s.logger.Infof(ctx, "Success semgrep scan: repository=%s, findings=%d", repository, len(findings))
	return findings, nil
}

func ParseSemgrepResult(dir, scanResult, repository, masterBranch, githubBaseURL string) ([]*SemgrepFinding, error) {
	var results SemgrepResults
	err := json.Unmarshal([]byte(scanResult), &results)
	if err != nil {
		return nil, err
	}
	findings := make([]*SemgrepFinding, 0, len(results.Results))
	for _, r := range results.Results {
		r.Repository = repository
		r.Path = strings.ReplaceAll(r.Path, dir+"/", "") // remove dir prefix
		r.GitHubURL = GenerateGitHubURL(githubBaseURL, masterBranch, r)
		findings = append(findings, r)
	}
	return findings, nil
}

func extractSemgrepMetadata(metadata any) *SemgrepMetadata {
	meta, ok := metadata.(map[string]interface{})
	if !ok {
		return &SemgrepMetadata{}
	}

	var m SemgrepMetadata
	if v, ok := meta["likelihood"]; ok {
		m.Likelihood = fmt.Sprintf("%v", v)
	}
	if v, ok := meta["impact"]; ok {
		m.Impact = fmt.Sprintf("%v", v)
	}
	return &m
}

func GetScoreSemgrep(serverity, likelihood, impact string) float32 {
	switch serverity {
	case "WARNING":
		return 0.3
	case "INFO":
		return 0.1
	}
	if serverity != "ERROR" {
		return 0.0
	}

	// severity "ERROR"
	// Fine-grained scoring
	if impact == "HIGH" && likelihood == "HIGH" {
		return 0.8
	} else if impact == "HIGH" {
		return 0.6
	} else if impact == "MEDIUM" {
		return 0.5
	} else if impact == "LOW" {
		return 0.4
	}
	return 0.6 // default ERROR score
}

func GenerateDataSourceIDForSemgrep(f *SemgrepFinding) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%s/start-%d-%d/end-%d-%d", f.Repository, f.Path, f.CheckID, f.Start.Line, f.Start.Column, f.End.Line, f.End.Column)))
	return hex.EncodeToString(hash[:])
}

func GenerateGitHubURL(githubBaseURL, masterBranch string, f *SemgrepFinding) string {
	baseURL := "https://github.com/"
	if githubBaseURL != "" {
		baseURL = githubBaseURL
	}
	return fmt.Sprintf("%s%s/blob/%s/%s#L%d-L%d", baseURL, f.Repository, masterBranch, f.Path, f.Start.Line, f.End.Line)
}

type SemgrepResults struct {
	Results []*SemgrepFinding `json:"results,omitempty"`
}

type SemgrepFinding struct {
	Repository     string        `json:"repository,omitempty"`
	RepoVisibility string        `json:"repo_visibility,omitempty"`
	GitHubURL      string        `json:"github_url,omitempty"`
	CheckID        string        `json:"check_id,omitempty"`
	Path           string        `json:"path,omitempty"`
	Start          *SemgrepLine  `json:"start,omitempty"`
	End            *SemgrepLine  `json:"end,omitempty"`
	Extra          *SemgrepExtra `json:"extra,omitempty"`
}

type SemgrepLine struct {
	Line   int `json:"line,omitempty"`
	Column int `json:"col,omitempty"`
	Offset int `json:"offset,omitempty"`
}
type SemgrepExtra struct {
	EngineKind    string      `json:"engine_kind,omitempty"`
	Fingerprint   string      `json:"fingerprint,omitempty"`
	IsIgnored     bool        `json:"is_ignored,omitempty"`
	Lines         string      `json:"lines,omitempty"`
	Message       string      `json:"message,omitempty"`
	Severity      string      `json:"severity,omitempty"`
	ValidateState string      `json:"validate_state,omitempty"`
	Metadata      interface{} `json:"metadata,omitempty"`
}

// SemgrepMetadata is a struct for semgrep metadata.
// If `security` category, a metadata has `likelihood` and `impact` fields(required fields).
// refs: https://semgrep.dev/docs/contributing/contributing-to-semgrep-rules-repository/#including-fields-required-by-security-category
type SemgrepMetadata struct {
	Likelihood string `json:"likelihood,omitempty"`
	Impact     string `json:"impact,omitempty"`
}
