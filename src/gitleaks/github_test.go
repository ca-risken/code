package main

import (
	"reflect"
	"testing"

	"github.com/google/go-github/v44/github"
)

func TestSetRepository(t *testing.T) {
	repository := []*github.Repository{
		{Name: github.String("something")},
		{Name: github.String("keyword")},
		{Name: github.String("prefix-keyword")},
		{Name: github.String("keyword-suffix")},
		{Name: github.String("prefix-keyword-suffix")},
	}
	cases := []struct {
		name  string
		input string
		want  *[]repositoryFinding
	}{
		{
			name:  "OK Blank filter",
			input: "",
			want: &[]repositoryFinding{
				{Name: github.String("something")},
				{Name: github.String("keyword")},
				{Name: github.String("prefix-keyword")},
				{Name: github.String("keyword-suffix")},
				{Name: github.String("prefix-keyword-suffix")},
			},
		},
		{
			name:  "OK filter match some repo",
			input: "keyword",
			want: &[]repositoryFinding{
				// {Name: github.String("something")},
				{Name: github.String("keyword")},
				{Name: github.String("prefix-keyword")},
				{Name: github.String("keyword-suffix")},
				{Name: github.String("prefix-keyword-suffix")},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := &[]repositoryFinding{}
			setRepositoryFinding(repository, c.input, got)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
