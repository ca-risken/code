package codescan

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGenerateGitHubURL(t *testing.T) {
	type args struct {
		baseURL      string
		masterBranch string
		finding      *SemgrepFinding
	}

	cases := []struct {
		name  string
		input *args
		want  string
	}{
		{
			name: "OK GitHub URL",
			input: &args{
				baseURL:      "",
				masterBranch: "main",
				finding: &SemgrepFinding{
					Repository: "org/repo",
					Path:       "aaa.go",
					Start: &SemgrepLine{
						Line: 1,
					},
					End: &SemgrepLine{
						Line: 2,
					},
				},
			},
			want: "https://github.com/org/repo/blob/main/aaa.go#L1-L2",
		},

		{
			name: "OK Custom URL",
			input: &args{
				baseURL:      "https://hostname/api/v3/",
				masterBranch: "master",
				finding: &SemgrepFinding{
					Repository: "org/repo",
					Path:       "aaa.go",
					Start: &SemgrepLine{
						Line: 1,
					},
					End: &SemgrepLine{
						Line: 2,
					},
				},
			},
			want: "https://hostname/api/v3/org/repo/blob/master/aaa.go#L1-L2",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GenerateGitHubURL(c.input.baseURL, c.input.masterBranch, c.input.finding)
			if got != c.want {
				t.Fatalf("Unexpected data match: want=%s, got=%s", c.want, got)
			}
		})
	}
}

func TestGetScoreSemgrep(t *testing.T) {
	type args struct {
		serverity  string
		likelihood string
		impact     string
	}
	cases := []struct {
		name  string
		input *args
		want  float32
	}{
		{
			name: "ERROR(likelihood: HIGH, impact: HIGH)",
			input: &args{
				serverity:  "ERROR",
				likelihood: "HIGH",
				impact:     "HIGH",
			},
			want: 0.7,
		},
		{
			name: "ERROR(likelihood: HIGH, impact: MEDIUM)",
			input: &args{
				serverity:  "ERROR",
				likelihood: "HIGH",
				impact:     "MEDIUM",
			},
			want: 0.6,
		},
		{
			name: "ERROR(likelihood: HIGH, impact: LOW)",
			input: &args{
				serverity:  "ERROR",
				likelihood: "HIGH",
				impact:     "LOW",
			},
			want: 0.5,
		},
		{
			name: "ERROR(likelihood: MEDIUM, impact: HIGH)",
			input: &args{
				serverity:  "ERROR",
				likelihood: "MEDIUM",
				impact:     "HIGH",
			},
			want: 0.6,
		},
		{
			name: "ERROR(likelihood: MEDIUM, impact: MEDIUM)",
			input: &args{
				serverity:  "ERROR",
				likelihood: "MEDIUM",
				impact:     "MEDIUM",
			},
			want: 0.5,
		},
		{
			name: "ERROR(likelihood: MEDIUM, impact: LOW)",
			input: &args{
				serverity:  "ERROR",
				likelihood: "MEDIUM",
				impact:     "LOW",
			},
			want: 0.4,
		},
		{
			name: "ERROR(likelihood: LOW, impact: HIGH)",
			input: &args{
				serverity:  "ERROR",
				likelihood: "LOW",
				impact:     "HIGH",
			},
			want: 0.5,
		},
		{
			name: "ERROR(likelihood: LOW, impact: MEDIUM)",
			input: &args{
				serverity:  "ERROR",
				likelihood: "LOW",
				impact:     "MEDIUM",
			},
			want: 0.4,
		},
		{
			name: "ERROR(likelihood: LOW, impact: LOW)",
			input: &args{
				serverity:  "ERROR",
				likelihood: "LOW",
				impact:     "LOW",
			},
			want: 0.3,
		},
		{
			name: "WARNING",
			input: &args{
				serverity: "WARNING",
			},
			want: 0.3,
		},
		{
			name: "INFO",
			input: &args{
				serverity: "INFO",
			},
			want: 0.1,
		},
		{
			name: "UNKNOWN",
			input: &args{
				serverity: "UNKNOWN",
			},
			want: 0.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetScoreSemgrep(c.input.serverity, c.input.likelihood, c.input.impact)
			if got != c.want {
				t.Fatalf("Unexpected data match: want=%f, got=%f", c.want, got)
			}
		})
	}
}

func TestGenerateDataSourceIDForSemgrep(t *testing.T) {
	type args struct {
		finding *SemgrepFinding
	}
	cases := []struct {
		name  string
		input *args
		want  string
	}{
		{
			name: "OK",
			input: &args{
				finding: &SemgrepFinding{
					Repository: "org/repo",
					Path:       "aaa.go",
					CheckID:    "check_id",
					Start: &SemgrepLine{
						Line:   1,
						Column: 2,
					},
					End: &SemgrepLine{
						Line:   3,
						Column: 4,
					},
				},
			},
			want: "244abeb5568f762c28a022722f6f18efc405c5f59231245bb22eb843ac446dd2",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GenerateDataSourceIDForSemgrep(c.input.finding)
			if got != c.want {
				t.Fatalf("Unexpected data match: want=%s, got=%s", c.want, got)
			}
		})
	}
}

func TestParseSemgrepResult(t *testing.T) {
	type args struct {
		dir           string
		scanResult    string
		repository    string
		masterBranch  string
		githubBaseURL string
	}
	cases := []struct {
		name  string
		input *args
		want  []*SemgrepFinding
	}{
		{
			name: "OK",
			input: &args{
				dir:          "/tmp",
				scanResult:   `{"results":[{"repository": "org/repo", "path": "/tmp/aaa.go", "check_id": "check_id", "start": {"line": 1, "col": 2}, "end": {"line": 3, "col": 4}, "extra": {"lines": "lines", "message": "message", "severity": "severity", "metadata": "metadata"}}]}`,
				masterBranch: "main",
				repository:   "org/repo",
			},
			want: []*SemgrepFinding{
				{
					Repository: "org/repo",
					GitHubURL:  "https://github.com/org/repo/blob/main/aaa.go#L1-L3",
					Path:       "aaa.go",
					CheckID:    "check_id",
					Start: &SemgrepLine{
						Line:   1,
						Column: 2,
					},
					End: &SemgrepLine{
						Line:   3,
						Column: 4,
					},
					Extra: &SemgrepExtra{
						Lines:    "lines",
						Message:  "message",
						Severity: "severity",
						Metadata: "metadata",
					},
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseSemgrepResult(c.input.dir, c.input.scanResult, c.input.repository, c.input.masterBranch, c.input.githubBaseURL)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("Unexpected data length: want=%d, got=%d", len(c.want), len(got))
			}
			if diff := cmp.Diff(got, c.want); diff != "" {
				t.Errorf("Unexpected value, diff=%s", diff)
			}
		})
	}
}

func TestExtractSemgrepMetadata(t *testing.T) {
	type args struct {
		metadata interface{}
	}
	cases := []struct {
		name  string
		input *args
		want  *SemgrepMetadata
	}{
		{
			name: "OK",
			input: &args{
				metadata: interface{}(map[string]interface{}{
					"likelihood": "HIGH",
					"impact":     "HIGH",
				}),
			},
			want: &SemgrepMetadata{
				Likelihood: "HIGH",
				Impact:     "HIGH",
			},
		},
		{
			name: "Empty",
			input: &args{
				metadata: ``,
			},
			want: &SemgrepMetadata{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractSemgrepMetadata(c.input.metadata)
			if diff := cmp.Diff(got, c.want); diff != "" {
				t.Errorf("Unexpected value, diff=%s", diff)
			}
		})
	}
}
