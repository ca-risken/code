package codescan

import (
	"reflect"
	"testing"
)

func TestGetRecommend(t *testing.T) {
	type args struct {
		repoName       string
		fileName       string
		rule           string
		semgrepMessage string
		githubURL      string
		line           string
	}

	cases := []struct {
		name  string
		input *args
		want  *recommend
	}{
		{
			name: "OK Blank",
			input: &args{
				repoName:       "REPO_NAME",
				fileName:       "FILE_NAME",
				rule:           "RULE",
				semgrepMessage: "MESSAGE",
				githubURL:      "https://github.com/ca-risken/",
				line:           "LINE",
			},
			want: &recommend{
				Risk: `A problem code detected in FILE_NAME file in REPO_NAME repository.
- DetectedRule: RULE
- MESSAGE`,
				Recommendation: `Take the following actions
- Check the source code.
	- GitHub URL: https://github.com/ca-risken/
	- Specific code line:
` + "```" + `
LINE
` + "```" + `
- Fix the source code with the following message.
	- MESSAGE`,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetSemgrepRecommend(c.input.repoName, c.input.fileName, c.input.rule, c.input.semgrepMessage, c.input.githubURL, c.input.line)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
