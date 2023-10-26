package codescan

import (
	"testing"
)

func TestGenerateGitHubURL(t *testing.T) {
	type args struct {
		baseURL string
		finding *semgrepFinding
	}

	cases := []struct {
		name  string
		input *args
		want  string
	}{
		{
			name: "OK GitHub URL",
			input: &args{
				baseURL: "",
				finding: &semgrepFinding{
					Repository: "org/repo",
					Path:       "aaa.go",
					Start: &semgrepLine{
						Line: 1,
					},
					End: &semgrepLine{
						Line: 2,
					},
				},
			},
			want: "https://github.com/org/repo/blob/master/aaa.go#L1-L2",
		},

		{
			name: "OK Custom URL",
			input: &args{
				baseURL: "https://hostname/api/v3/",
				finding: &semgrepFinding{
					Repository: "org/repo",
					Path:       "aaa.go",
					Start: &semgrepLine{
						Line: 1,
					},
					End: &semgrepLine{
						Line: 2,
					},
				},
			},
			want: "https://hostname/api/v3/org/repo/blob/master/aaa.go#L1-L2",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := generateGitHubURL(c.input.baseURL, c.input.finding)
			if got != c.want {
				t.Fatalf("Unexpected data match: want=%s, got=%s", c.want, got)
			}
		})
	}
}
