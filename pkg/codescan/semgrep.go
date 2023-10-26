package codescan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-github/v44/github"
)

func (s *sqsHandler) scanForRepository(ctx context.Context, projectID uint32, r *github.Repository, token, githubBaseURL string) ([]*semgrepFinding, error) {
	// Clone repository
	dir, err := createCloneDir(*r.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create directory to clone: repo=%s err=%w", *r.FullName, err)
	}
	defer os.RemoveAll(dir)

	err = s.githubClient.Clone(ctx, token, *r.CloneURL, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to clone: repo=%s err=%w", *r.FullName, err)
	}

	// Scemgrep
	findings, err := s.semgrepScan(ctx, dir, *r.FullName, githubBaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to scan: repo=%s  err=%w", *r.FullName, err)
	}
	return findings, nil
}

func (s *sqsHandler) semgrepScan(ctx context.Context, targetDir, repository, githubBaseURL string) ([]*semgrepFinding, error) {
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
	findings, err := parseSemgrepResult(targetDir, stdout.String(), repository, githubBaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep: targetDir=%s, err=%w", targetDir, err)
	}
	s.logger.Infof(ctx, "Success semgrep scan: repository=%s, findings=%d", repository, len(findings))
	return findings, nil
}

func parseSemgrepResult(dir, scanResult, repository, githubBaseURL string) ([]*semgrepFinding, error) {
	var results semgrepResults
	err := json.Unmarshal([]byte(scanResult), &results)
	if err != nil {
		return nil, err
	}
	findings := make([]*semgrepFinding, 0, len(results.Results))
	for _, r := range results.Results {
		r.Repository = repository
		r.Path = strings.ReplaceAll(r.Path, dir+"/", "") // remove dir prefix
		r.GitHubURL = generateGitHubURL(githubBaseURL, r)
		findings = append(findings, r)
	}
	return findings, nil
}

func getScoreSemgrep(serverity string) float32 {
	switch serverity {
	case "ERROR":
		return 0.6
	case "WARNING":
		return 0.3
	case "INFO":
		return 0.1
	default:
		return 0.0
	}
}

func generateDataSourceIDForSemgrep(f *semgrepFinding) string {
	return fmt.Sprintf("%s/%s/%s/start-%d-%d/end-%d-%d", f.Repository, f.Path, f.CheckID, f.Start.Line, f.Start.Column, f.End.Line, f.End.Column)
}

func generateGitHubURL(githubBaseURL string, f *semgrepFinding) string {
	baseURL := "https://github.com/"
	if githubBaseURL != "" {
		baseURL = githubBaseURL
	}
	return fmt.Sprintf("%s%s/blob/master/%s#L%d-L%d", baseURL, f.Repository, f.Path, f.Start.Line, f.End.Line)
}

type semgrepResults struct {
	Results []*semgrepFinding `json:"results,omitempty"`
}

type semgrepFinding struct {
	Repository     string        `json:"repository,omitempty"`
	RepoVisibility string        `json:"repo_visibility,omitempty"`
	GitHubURL      string        `json:"github_url,omitempty"`
	CheckID        string        `json:"check_id,omitempty"`
	Path           string        `json:"path,omitempty"`
	Start          *semgrepLine  `json:"start,omitempty"`
	End            *semgrepLine  `json:"end,omitempty"`
	Extra          *semgrepExtra `json:"extra,omitempty"`
}

type semgrepLine struct {
	Line   int `json:"line,omitempty"`
	Column int `json:"col,omitempty"`
	Offset int `json:"offset,omitempty"`
}
type semgrepExtra struct {
	EngineKind    string      `json:"engine_kind,omitempty"`
	Fingerprint   string      `json:"fingerprint,omitempty"`
	IsIgnored     bool        `json:"is_ignored,omitempty"`
	Lines         string      `json:"lines,omitempty"`
	Message       string      `json:"message,omitempty"`
	Severity      string      `json:"severity,omitempty"`
	ValidateState string      `json:"validate_state,omitempty"`
	Metadata      interface{} `json:"metadata,omitempty"`
}
