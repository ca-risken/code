package gitleaks

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/ca-risken/core/proto/ai"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/go-git/go-git/v5"
	"github.com/zricethezav/gitleaks/v8/report"
	"google.golang.org/grpc/status"
)

const (
	classificationBudget = 30 * time.Second
	maxCoreTextBytes     = 32768
)

type classification struct {
	TestData    *bool    `json:"test_data,omitzero"`
	Categories  []string `json:"categories"`
	Sensitivity *bool    `json:"sensitivity,omitzero"`
	ContentKind string   `json:"content_kind,omitempty"`
}

func (s *sqsHandler) classifyFindings(ctx context.Context, dir string, findings []*GitleaksFinding, scan scanReport, setting *code.GitleaksSetting) {
	if !setting.GetAiScan() || len(findings) == 0 {
		return
	}
	repo, err := git.PlainOpen(dir)
	if err != nil {
		s.logger.Warnf(ctx, "Failed to open cloned repository for Gitleaks classification")
		return
	}

	ctx, cancel := context.WithTimeout(ctx, classificationBudget)
	defer cancel()
	for i, f := range findings {
		if ctx.Err() != nil {
			break
		}
		leak := scan.findings[i]
		req, err := readFindingSample(ctx, repo, leak, scan.rules[leak.RuleID])
		if err != nil {
			s.logger.Warnf(ctx, "Failed to read Gitleaks finding sample, data_source_id=%s, err=%v", f.Result.DataSourceID, err)
			continue
		}
		if req == nil || req.Validate() != nil {
			continue
		}
		// Recheck on every submission so an opt-out also takes effect between
		// findings in an already queued or running scan.
		current, err := s.getGitHubSetting(ctx, setting.GetProjectId(), setting.GetGithubSettingId())
		if err != nil {
			s.logger.Warnf(ctx, "Could not confirm Gitleaks AI scan setting, github_setting_id=%d", setting.GetGithubSettingId())
			return
		}
		if !current.GetGitleaksSetting().GetAiScan() {
			return
		}
		result, err := s.aiClient.ClassifySensitiveContent(ctx, req)
		if err != nil {
			s.logger.Warnf(ctx, "Failed to classify Gitleaks finding, data_source_id=%s, code=%s", f.Result.DataSourceID, status.Code(err))
			continue
		}
		f.AIClassification = newClassification(result)
	}
}

func newClassification(result *ai.ClassifySensitiveContentResponse) *classification {
	if result == nil {
		return nil
	}
	value := &classification{Categories: make([]string, 0, len(result.GetCategories()))}
	switch result.GetTestData() {
	case ai.TestData_TEST_DATA_TRUE:
		value.TestData = new(true)
	case ai.TestData_TEST_DATA_FALSE:
		value.TestData = new(false)
	}
	switch result.GetSensitivity() {
	case ai.Sensitivity_SENSITIVITY_TRUE:
		value.Sensitivity = new(true)
	case ai.Sensitivity_SENSITIVITY_FALSE:
		value.Sensitivity = new(false)
	}
	if kind, ok := strings.CutPrefix(result.GetContentKind().String(), "CONTENT_KIND_"); ok {
		value.ContentKind = kind
	}
	for _, category := range result.GetCategories() {
		if name, ok := strings.CutPrefix(category.String(), "SENSITIVE_CONTENT_CATEGORY_"); ok && name != "UNSPECIFIED" {
			value.Categories = append(value.Categories, name)
		}
	}
	return value
}

func findingSample(contents []byte, leak report.Finding) *ai.ClassifySensitiveContentRequest {
	var lineNumber, offset, matchStart, matchEnd int
	for line := range bytes.Lines(contents) {
		lineNumber++
		if lineNumber == leak.StartLine {
			matchStart = offset
		}
		offset += len(line)
		if lineNumber == leak.EndLine {
			matchEnd = offset
			break
		}
	}
	if matchEnd <= matchStart || len(bytes.TrimSpace(contents[matchStart:matchEnd])) == 0 {
		return nil
	}
	scope := fmt.Sprintf("Assess only the detected value in lines %d through %d of the supplied text, counting from line 1.", leak.StartLine, leak.EndLine)
	if leak.StartColumn > 0 && leak.EndColumn > 0 {
		scope += fmt.Sprintf(" The detector locates the match near byte column %d of the first target line and byte column %d of the last target line.",
			leak.StartColumn, leak.EndColumn)
	}
	return classificationRequest(leak.File, contents, scope)
}

func classificationRequest(file string, text []byte, scope string) *ai.ClassifySensitiveContentRequest {
	return &ai.ClassifySensitiveContentRequest{
		FileName: path.Base(file),
		Text:     string(text),
		CustomPrompt: "For sensitivity, categories, and test_data: " + scope +
			" Use the rest of the supplied text only as evidence about that value." +
			" For sensitivity and categories, count populated values that represent credentials, including published examples and synthetic fixtures." +
			" For test_data, a comment that explicitly identifies the detected value as a synthetic fixture or published example is evidence about its origin." +
			" For content_kind, classify the supplied text as a whole.",
	}
}
