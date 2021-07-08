package common

import (
	"reflect"
	"testing"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		input   *GitleaksQueueMessage
		wantErr bool
	}{
		{
			name:  "OK",
			input: &GitleaksQueueMessage{GitleaksID: 1, ProjectID: 1},
		},
		{
			name:  "OK(scan_only)",
			input: &GitleaksQueueMessage{GitleaksID: 1, ProjectID: 1, ScanOnly: true},
		},
		{
			name:    "NG Required(gitlekas_id)",
			input:   &GitleaksQueueMessage{ProjectID: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(project_id)",
			input:   &GitleaksQueueMessage{GitleaksID: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestParseMessage(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    *GitleaksQueueMessage
		wantErr bool
	}{
		{
			name:  "OK",
			input: `{"gitleaks_id":1, "project_id":1}`,
			want:  &GitleaksQueueMessage{GitleaksID: 1, ProjectID: 1},
		},
		{
			name:  "OK(scan_only)",
			input: `{"gitleaks_id":1, "project_id":1, "scan_only":"true"}`,
			want:  &GitleaksQueueMessage{GitleaksID: 1, ProjectID: 1, ScanOnly: true},
		},
		{
			name:    "NG Json parse erroro",
			input:   `{"parse...: error`,
			wantErr: true,
		},
		{
			name:    "NG Invalid mmessage(required parammeter)",
			input:   `{}`,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseMessage(c.input)
			if err != nil && !c.wantErr {
				t.Fatalf("Unexpected error occured, wantErr=%t, err=%+v", c.wantErr, err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpaeted response, want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
