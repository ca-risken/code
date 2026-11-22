package gitleaks

import (
	"context"
	"crypto/sha256"
	json "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	githubcli "github.com/ca-risken/code/pkg/github"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/core/proto/ai"
	"github.com/ca-risken/datasource-api/proto/code"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v44/github"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type classificationClient func(*ai.ClassifySensitiveContentRequest) (*ai.ClassifySensitiveContentResponse, error)

func (f classificationClient) ClassifySensitiveContent(_ context.Context, req *ai.ClassifySensitiveContentRequest, _ ...grpc.CallOption) (*ai.ClassifySensitiveContentResponse, error) {
	return f(req)
}

type classificationSettingsClient struct {
	code.CodeServiceClient
	get func(*code.GetGitHubSettingRequest) (*code.GetGitHubSettingResponse, error)
}

func (c classificationSettingsClient) GetGitHubSetting(_ context.Context, req *code.GetGitHubSettingRequest, _ ...grpc.CallOption) (*code.GetGitHubSettingResponse, error) {
	return c.get(req)
}

type classificationScan func() []report.Finding

func (f classificationScan) scan(context.Context, string, *scanDuration) (scanReport, error) {
	return scanReport{findings: f()}, nil
}

type classificationClone struct {
	githubcli.GithubServiceClient
	sourceDir string
}

func (c classificationClone) Clone(ctx context.Context, _, _ string, dstDir string) error {
	_, err := git.PlainCloneContext(ctx, dstDir, false, &git.CloneOptions{URL: c.sourceDir})
	return err
}

func TestScanRepository_ClassifiesFinding(t *testing.T) {
	const (
		file       = "examples dir/config#demo.env"
		secret     = "example-only"
		sample     = "  API_KEY=" + secret + " # test fixture\n  MODE=demo"
		before     = "# demo setup"
		after      = "OTHER_KEY=another-example-value # unrelated finding"
		commitText = before + "\n" + sample + "\n" + after + "\n"
	)
	sourceDir, commit := createClassificationRepository(t, file, commitText)
	classification := &ai.ClassifySensitiveContentResponse{
		Sensitivity: ai.Sensitivity_SENSITIVITY_TRUE,
		Categories: []ai.SensitiveContentCategory{
			ai.SensitiveContentCategory_SENSITIVE_CONTENT_CATEGORY_PII,
			ai.SensitiveContentCategory_SENSITIVE_CONTENT_CATEGORY_CREDENTIAL,
		},
		ContentKind: ai.ContentKind_CONTENT_KIND_CONFIGURATION,
		TestData:    ai.TestData_TEST_DATA_TRUE,
	}
	wantClassification := map[string]any{
		"sensitivity":  true,
		"categories":   []any{"PII", "CREDENTIAL"},
		"content_kind": "CONFIGURATION",
		"test_data":    true,
	}
	on, off := new(true), new(false)
	tests := []struct {
		name          string
		visibility    string
		result        *ai.ClassifySensitiveContentResponse
		classifyErr   error
		settingErr    error
		initialAIScan *bool
		turnedOff     bool
		endLine       int
		wantCalls     int
		wantScore     float32
		wantDecision  map[string]any
	}{
		{
			name: "public test data", visibility: "public", initialAIScan: on, endLine: 3, result: classification,
			wantCalls: 1, wantScore: 0.6, wantDecision: wantClassification,
		},
		{
			name: "internal test data", visibility: "internal", initialAIScan: on, endLine: 3, result: classification,
			wantCalls: 1, wantScore: 0.6, wantDecision: wantClassification,
		},
		{
			name: "private test data", visibility: "private", initialAIScan: on, endLine: 3, result: classification,
			wantCalls: 1, wantScore: 0.6, wantDecision: wantClassification,
		},
		{
			name: "inconclusive decision", visibility: "private", initialAIScan: on, endLine: 3,
			result: &ai.ClassifySensitiveContentResponse{}, wantCalls: 1, wantScore: 0.8,
			wantDecision: map[string]any{
				"categories": []any{}, "content_kind": "UNSPECIFIED",
			},
		},
		{
			name: "real value in an example configuration", visibility: "private", initialAIScan: on, endLine: 3,
			wantCalls: 1, wantScore: 0.8,
			result: &ai.ClassifySensitiveContentResponse{
				Sensitivity: ai.Sensitivity_SENSITIVITY_TRUE,
				TestData:    ai.TestData_TEST_DATA_FALSE,
			},
			wantDecision: map[string]any{
				"sensitivity": true, "categories": []any{},
				"content_kind": "UNSPECIFIED", "test_data": false,
			},
		},
		{
			name: "non-sensitive value", visibility: "private", initialAIScan: on, endLine: 3,
			wantCalls: 1, wantScore: 0.3,
			result: &ai.ClassifySensitiveContentResponse{Sensitivity: ai.Sensitivity_SENSITIVITY_FALSE},
			wantDecision: map[string]any{
				"sensitivity": false, "categories": []any{}, "content_kind": "UNSPECIFIED",
			},
		},
		{
			name: "no matching source lines", visibility: "private", initialAIScan: on, endLine: 8,
			wantScore: 0.8,
		},
		{
			name: "Core unavailable", visibility: "internal", initialAIScan: on, endLine: 3,
			classifyErr: status.Error(codes.Unavailable, "unavailable"), wantCalls: 1, wantScore: 0.8,
		},
		{
			name: "existing setting defaults to off", visibility: "private", endLine: 3,
			wantScore: 0.8,
		},
		{
			name: "explicitly disabled", visibility: "public", initialAIScan: off, endLine: 3,
			wantScore: 1.0,
		},
		{
			name: "setting turned off during scan", visibility: "private", initialAIScan: on, endLine: 3,
			turnedOff: true, wantScore: 0.8,
		},
		{
			name: "setting could not be confirmed", visibility: "private", initialAIScan: on, endLine: 3,
			settingErr: status.Error(codes.Unavailable, "unavailable"), wantScore: 0.8,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			settingReads := 0
			setting := &code.GitleaksSetting{GithubSettingId: 123, ProjectId: 456, AiScan: tt.initialAIScan}
			handler := &sqsHandler{
				logger:       logging.NewLogger(),
				githubClient: classificationClone{sourceDir: sourceDir},
				codeClient: classificationSettingsClient{get: func(req *code.GetGitHubSettingRequest) (*code.GetGitHubSettingResponse, error) {
					settingReads++
					if req.GetGithubSettingId() != setting.GetGithubSettingId() || req.GetProjectId() != setting.GetProjectId() {
						t.Fatal("latest setting was read for a different GitHub setting")
					}
					if tt.settingErr != nil {
						return nil, tt.settingErr
					}
					latestAIScan := tt.initialAIScan
					if tt.turnedOff {
						latestAIScan = off
					}
					return &code.GetGitHubSettingResponse{GithubSetting: &code.GitHubSetting{
						GitleaksSetting: &code.GitleaksSetting{AiScan: latestAIScan},
					}}, nil
				}},
				gitleaksClient: classificationScan(func() []report.Finding {
					return []report.Finding{{
						Commit: commit, File: file, StartLine: 2, EndLine: tt.endLine,
						StartColumn: 3, EndColumn: 11,
						Secret: secret, Message: "dummy value " + secret,
					}}
				}),
				aiClient: classificationClient(func(req *ai.ClassifySensitiveContentRequest) (*ai.ClassifySensitiveContentResponse, error) {
					calls++
					if diff := cmp.Diff(commitText, req.GetText()); diff != "" {
						t.Errorf("unexpected sample (-want +got):\n%s", diff)
					}
					if diff := cmp.Diff("config#demo.env", req.GetFileName()); diff != "" {
						t.Errorf("unexpected file name (-want +got):\n%s", diff)
					}
					if !strings.Contains(req.GetCustomPrompt(), "lines 2 through 3") ||
						!strings.Contains(req.GetCustomPrompt(), "byte column 3 of the first target line and byte column 11 of the last target line") ||
						!strings.Contains(req.GetCustomPrompt(), "Use the rest of the supplied text only as evidence about that value") {
						t.Errorf("unexpected custom prompt %q", req.GetCustomPrompt())
					}
					return tt.result, tt.classifyErr
				}),
			}
			now := github.Timestamp{Time: time.Now()}
			repo := &github.Repository{
				Name:       new("repo"),
				FullName:   new("owner/repo"),
				HTMLURL:    new("https://github.com/owner/repo"),
				CloneURL:   new("https://github.com/owner/repo.git"),
				Visibility: new(tt.visibility),
				Private:    new(tt.visibility == "private"),
				CreatedAt:  &now,
				PushedAt:   &now,
			}
			findings, _, err := handler.scanRepository(t.Context(), repo, "", nil, setting)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if calls != tt.wantCalls {
				t.Errorf("Core calls = %d, want %d", calls, tt.wantCalls)
			}
			wantReads := 0
			if setting.GetAiScan() && tt.endLine == 3 {
				wantReads = 1
			}
			if settingReads != wantReads {
				t.Errorf("consent checks = %d, want %d", settingReads, wantReads)
			}
			original := &LeakFinding{
				Repo: "owner/repo", Commit: commit, Secret: secret, File: file,
				StartLine: 2, EndLine: tt.endLine, StartColumn: 3,
			}
			if got, want := findings[0].Result.DataSourceID, original.GenerateDataSourceID(); got != want {
				t.Errorf("data source ID = %s, want %s", got, want)
			}

			req, err := GeneratePutFindingRequest(1, findings[0])
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.wantScore, req.GetFinding().GetOriginalScore()); diff != "" {
				t.Errorf("unexpected score (-want +got):\n%s", diff)
			}
			var data struct {
				AIClassification map[string]any `json:"ai_classification"`
				Results          LeakFinding    `json:"results"`
			}
			if err := json.Unmarshal([]byte(req.GetFinding().GetData()), &data); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.wantDecision, data.AIClassification); diff != "" {
				t.Errorf("unexpected stored decision (-want +got):\n%s", diff)
			}
			if data.Results.Secret != redactedSecret || strings.Contains(req.GetFinding().GetData(), secret) ||
				strings.Contains(req.GetFinding().GetData(), before) || strings.Contains(req.GetFinding().GetData(), after) {
				t.Error("finding JSON contains evidence or lacks the redaction marker")
			}
		})
	}
}

func TestClassifyFindingsStopsAfterOptOut(t *testing.T) {
	dir, commit := createClassificationRepository(t, "example.env", "TOKEN=example-only\n")
	leak := report.Finding{Commit: commit, File: "example.env", StartLine: 1, EndLine: 1}
	findings := []*GitleaksFinding{{Result: &LeakFinding{}}, {Result: &LeakFinding{}}}
	settingReads, aiCalls := 0, 0
	handler := &sqsHandler{
		logger: logging.NewLogger(),
		codeClient: classificationSettingsClient{get: func(_ *code.GetGitHubSettingRequest) (*code.GetGitHubSettingResponse, error) {
			settingReads++
			return &code.GetGitHubSettingResponse{GithubSetting: &code.GitHubSetting{
				GitleaksSetting: &code.GitleaksSetting{AiScan: new(settingReads == 1)},
			}}, nil
		}},
		aiClient: classificationClient(func(_ *ai.ClassifySensitiveContentRequest) (*ai.ClassifySensitiveContentResponse, error) {
			aiCalls++
			return &ai.ClassifySensitiveContentResponse{}, nil
		}),
	}
	handler.classifyFindings(t.Context(), dir, findings, scanReport{findings: []report.Finding{leak, leak}},
		&code.GitleaksSetting{GithubSettingId: 123, ProjectId: 456, AiScan: new(true)})
	if settingReads != 2 || aiCalls != 1 || findings[0].AIClassification == nil || findings[1].AIClassification != nil {
		t.Fatalf("expected only the finding sent before opt-out to be classified, reads = %d, calls = %d", settingReads, aiCalls)
	}
}

func TestReadLargeFindingSample(t *testing.T) {
	t.Parallel()

	const (
		secret   = "example-only"
		probe    = `apiKey = "` + secret + `"`
		marker   = "target context: "
		oldProbe = `otherKey = "` + secret + `"`
	)
	rule := &config.Rule{Regex: regexp.MustCompile(`apiKey = "([a-z-]+)"`), SecretGroup: 1}
	long := strings.Repeat("環", (1<<20)/3)
	tests := []struct {
		name       string
		source     string
		line       int
		column     int
		columnBias int
		rejected   bool
	}{
		{name: "first line of a large bundle", source: long + marker + probe + long, line: 1, column: len(long+marker) + 1},
		{name: "line after a newline", source: long + "\n" + marker + probe + long, line: 2, column: len(marker) + 1, columnBias: 1},
		{name: "match at the start of a file", source: probe + long, line: 1, column: 1},
		{name: "match at the end of a file", source: long + marker + probe, line: 1, column: len(long+marker) + 1},
		{name: "stale match at the reported columns", source: long + marker + oldProbe + long, line: 1, column: len(long+marker) + 1, rejected: true},
		{name: "reported column crosses a newline", source: "line\n" + long + marker + probe, line: 1, column: len("line\n"+long+marker) + 1, rejected: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			leak := report.Finding{
				File: "example.min.js", StartLine: tt.line, EndLine: tt.line, StartColumn: tt.column + tt.columnBias,
				EndColumn: tt.column + len(probe) - 1 + tt.columnBias, Match: probe, Secret: secret,
			}
			leak.Redact()
			req, err := readLargeFindingSample(t.Context(), strings.NewReader(tt.source), leak, rule)
			if err != nil || (req == nil) != tt.rejected {
				t.Fatalf("request present = %t, rejected = %t, err = %v", req != nil, tt.rejected, err)
			}
			if tt.rejected {
				return
			}
			sample := req.GetText()
			if len(sample) > len(secret)+2*findingContextBytes || !utf8.ValidString(sample) || !strings.Contains(sample, probe) {
				t.Fatal("sample must retain the match and bounded UTF-8 context")
			}
			if strings.Contains(tt.source, marker) && !strings.Contains(sample, marker) {
				t.Fatal("sample must retain the adjacent context")
			}
			position := strings.Index(sample, secret)
			wantScope := fmt.Sprintf("bytes %d through %d of the supplied text", position+1, position+len(secret))
			if !strings.Contains(req.GetCustomPrompt(), wantScope) || strings.Contains(req.GetCustomPrompt(), secret) {
				t.Errorf("unexpected target scope %q, want %q with no source value", req.GetCustomPrompt(), wantScope)
			}
			if err := req.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadFindingSampleFromGitScan(t *testing.T) {
	const filename = "static/bundle.min.js"
	first := fmt.Sprintf("%x", sha256.Sum256([]byte("first synthetic fixture")))
	second := fmt.Sprintf("%x", sha256.Sum256([]byte("second synthetic fixture")))
	assignments := fmt.Sprintf(`";const apiKey="%s";const clientSecret="%s";`, first, second)
	tests := []struct {
		name string
		size int
	}{
		{name: "exactly the full-text limit", size: maxCoreTextBytes},
		{name: "one minified line beyond one MiB", size: (1 << 20) + 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const prefix = `const filler="`
			source := prefix + strings.Repeat("x", tt.size-len(prefix)-len(assignments)) + assignments
			dir, commit := createClassificationRepository(t, filename, source)
			scan, err := newGitleaksClient(&gitleaksConfig{redact: true}).scan(t.Context(), dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(scan.findings) != 2 {
				t.Fatalf("Gitleaks findings = %d, want 2", len(scan.findings))
			}
			repo, err := git.PlainOpen(dir)
			if err != nil {
				t.Fatal(err)
			}
			var targets []string
			for _, leak := range scan.findings {
				if leak.Commit != commit || leak.Secret != redactedSecret {
					t.Fatal("expected a redacted finding from the detected commit")
				}
				req, err := readFindingSample(t.Context(), repo, leak, scan.rules[leak.RuleID])
				if err != nil || req == nil {
					t.Fatalf("classification request missing for %s at %d:%d–%d:%d, err = %v",
						leak.RuleID, leak.StartLine, leak.StartColumn, leak.EndLine, leak.EndColumn, err)
				}
				if err := req.Validate(); err != nil {
					t.Fatal(err)
				}
				sample := req.GetText()
				if tt.size <= maxCoreTextBytes {
					if sample != source {
						t.Fatal("request must contain the entire original file")
					}
					continue
				}
				_, scope, ok := strings.Cut(req.GetCustomPrompt(), "at bytes ")
				var start, end int
				n, err := fmt.Sscanf(scope, "%d through %d", &start, &end)
				if !ok || err != nil || n != 2 || start < 1 || end < start || end > len(sample) {
					t.Fatalf("missing or invalid target in prompt %q", req.GetCustomPrompt())
				}
				targets = append(targets, sample[start-1:end])
			}
			if tt.size > maxCoreTextBytes && !slices.Equal(slices.Sorted(slices.Values(targets)), slices.Sorted(slices.Values([]string{first, second}))) {
				t.Fatal("each prompt must select its own detected value")
			}
		})
	}
}

func createClassificationRepository(t *testing.T, file, contents string) (dir, commit string) {
	t.Helper()
	dir = t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(dir, file)
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	author := &object.Signature{Name: "Fixture", Email: "fixture@example.com", When: time.Now()}
	for _, text := range []string{contents, "changed contents at HEAD\n"} {
		if err := os.WriteFile(filename, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := worktree.Add(file); err != nil {
			t.Fatal(err)
		}
		hash, err := worktree.Commit("add fixture", &git.CommitOptions{Author: author})
		if err != nil {
			t.Fatal(err)
		}
		if commit == "" {
			commit = hash.String()
		}
	}
	return dir, commit
}
