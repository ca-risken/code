package main

import (
	"reflect"
	"testing"
)

func TestGetDefaultRecommend(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  *recommend
	}{
		{
			name:  "OK Blank",
			input: "test",
			want: &recommend{
				Risk: `test
		- If a key is leaked, a cyber attack is possible within the scope of the key's authority
		- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
				Recommendation: `Take the following actions for leaked keys
		- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
		- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
		- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getDefaultRecommend(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
