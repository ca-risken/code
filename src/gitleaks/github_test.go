package main

import (
	"reflect"
	"testing"

	"github.com/google/go-github/v32/github"
)

func TestFilterRepository(t *testing.T) {
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
		want  []*github.Repository
	}{
		{
			name:  "OK Blank filter",
			input: "",
			want:  repository,
		},
		{
			name:  "OK filter match some repo",
			input: "keyword",
			want: []*github.Repository{
				{Name: github.String("keyword")},
				{Name: github.String("prefix-keyword")},
				{Name: github.String("keyword-suffix")},
				{Name: github.String("prefix-keyword-suffix")},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := filterRepository(repository, c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
