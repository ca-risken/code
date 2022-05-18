package main

import (
	"reflect"
	"testing"

	"github.com/google/go-github/v44/github"
)

func TestScoreGitleaks(t *testing.T) {
	cases := []struct {
		name  string
		input *repositoryFinding
		want  float32
	}{
		{
			name:  "OK Blank",
			input: &repositoryFinding{},
			want:  0.1,
		},
		{
			name: "OK Exists leak",
			input: &repositoryFinding{
				Name: github.String("danger_repository"),
				LeakFindings: []*leakFinding{
					{Rule: "aaa"},
					{Rule: "bbb"},
				},
			},
			want: 0.6,
		},
		{
			name: "OK Exits critical tag",
			input: &repositoryFinding{
				Name: github.String("danger_repository"),
				LeakFindings: []*leakFinding{
					{Rule: "aaa"},
					{Rule: "Google (GCP) Service Account"}, // critical rule
				},
			},
			want: 0.8,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreGitleaks(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
