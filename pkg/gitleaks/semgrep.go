package gitleaks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ca-risken/core/proto/finding"
	"github.com/google/go-github/v44/github"
)

func (s *sqsHandler) semgrepRepository(ctx context.Context, projectID uint32, r *github.Repository, token string) error {
	// Clone repository
	dir, err := createCloneDir(*r.Name)
	if err != nil {
		return fmt.Errorf("failed to create directory to clone: repo=%s err=%w", *r.FullName, err)
	}
	defer os.RemoveAll(dir)

	err = s.githubClient.Clone(ctx, token, *r.CloneURL, dir)
	if err != nil {
		return fmt.Errorf("failed to clone: repo=%s err=%w", *r.FullName, err)
	}

	// Scan repository
	findings, err := s.semgrepScan(ctx, dir, *r.FullName)
	if err != nil {
		return fmt.Errorf("failed to scan: repo=%s  err=%w", *r.FullName, err)
	}

	// put findings
	err = s.putSemgrepFindings(ctx, projectID, findings)
	if err != nil {
		return fmt.Errorf("failed to put findings: repo=%s, err=%w", *r.FullName, err)
	}
	return nil
}

func (s *sqsHandler) semgrepScan(ctx context.Context, targetDir, repository string) ([]*semgrepFinding, error) {
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
	s.logger.Infof(ctx, "semgrep scan start: targetDir=%s", targetDir)

	err := cmd.Run()
	if err != nil {
		s.logger.Infof(ctx, "semgrep scan error: targetDir=%s", targetDir)
		return nil, fmt.Errorf("failed to execute semgrep: targetDir=%s, err=%w, stderr=%+v", targetDir, err, stderr.String())
	}
	s.logger.Infof(ctx, "semgrep scan success: targetDir=%s", targetDir)
	s.logger.Infof(ctx, "semgrep scan result: %s", stdout.String())
	findings, err := parseSemgrepResult(targetDir, stdout.String(), repository)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep targetDir=%s, result: %w", targetDir, err)
	}
	return findings, nil
}

func parseSemgrepResult(dir, scanResult, repository string) ([]*semgrepFinding, error) {
	var results semgrepResults
	err := json.Unmarshal([]byte(scanResult), &results)
	if err != nil {
		return nil, err
	}
	findings := make([]*semgrepFinding, 0, len(results.Results))
	for _, r := range results.Results {
		r.Repository = repository
		r.Path = strings.ReplaceAll(r.Path, dir+"/", "") // remove dir prefix
		findings = append(findings, r)
	}
	return findings, nil
}

func (s *sqsHandler) putSemgrepFindings(ctx context.Context, projectID uint32, findings []*semgrepFinding) error {
	for _, f := range findings {
		// finding
		buf, err := json.Marshal(f)
		if err != nil {
			return fmt.Errorf("failed to marshal data: project_id=%d, repository=%s, err=%w", projectID, f.Repository, err)
		}
		if _, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
			Finding: &finding.FindingForUpsert{
				Description:      fmt.Sprintf("Detect source code finding (%s)", f.CheckID),
				DataSource:       "code:sast",
				DataSourceId:     generateDataSourceIDForSemgrep(f),
				ResourceName:     f.Repository,
				ProjectId:        projectID,
				OriginalScore:    getScoreSemgrep(f.Extra.Severity),
				OriginalMaxScore: 1.0,
				Data:             string(buf),
			},
		}); err != nil {
			return err
		}
		// TODO finding-tag
		// TODO recommendation
	}
	return nil
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

type semgrepResults struct {
	Results []*semgrepFinding `json:"results,omitempty"`
}

type semgrepFinding struct {
	Repository string        `json:"repository,omitempty"`
	CheckID    string        `json:"check_id,omitempty"`
	Path       string        `json:"path,omitempty"`
	Start      *semgrepLine  `json:"start,omitempty"`
	End        *semgrepLine  `json:"end,omitempty"`
	Extra      *semgrepExtra `json:"extra,omitempty"`
}

type semgrepLine struct {
	Line   int `json:"line,omitempty"`
	Column int `json:"col,omitempty"`
	Offset int `json:"offset,omitempty"`
}
type semgrepExtra struct {
	EngineKind    string           `json:"engine_kind,omitempty"`
	Fingerprint   string           `json:"fingerprint,omitempty"`
	IsIgnored     bool             `json:"is_ignored,omitempty"`
	Lines         string           `json:"lines,omitempty"`
	Message       string           `json:"message,omitempty"`
	Severity      string           `json:"severity,omitempty"`
	ValidateState string           `json:"validate_state,omitempty"`
	Metadata      *semgrepMetadata `json:"metadata,omitempty"`
}
type semgrepMetadata struct {
	Category           string   `json:"category,omitempty"`
	SubCategory        []string `json:"sub_category,omitempty"`
	Impact             string   `json:"impact,omitempty"`
	Confidence         string   `json:"confidence,omitempty"`
	Source             string   `json:"source,omitempty"`
	SourceRuleURL      string   `json:"source_rule_url,omitempty"`
	CWE                []string `json:"cwe,omitempty"`
	Owasp              []string `json:"owasp,omitempty"`
	References         []string `json:"references,omitempty"`
	Technology         []string `json:"technology,omitempty"`
	VulnerabilityClass []string `json:"vulnerability_class,omitempty"`
}
