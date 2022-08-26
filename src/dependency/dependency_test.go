package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-github/v44/github"
	"k8s.io/utils/exec"
	fakeexec "k8s.io/utils/exec/testing"
)

type fakeTrivyClient struct {
	err error
}

func (f *fakeTrivyClient) scan(ctx context.Context, repo *github.Repository, token string, filePath string) error {
	return f.err
}

func makeFakeOutput(output string, err error) fakeexec.FakeAction {
	o := output
	return func() ([]byte, []byte, error) {
		return []byte(o), nil, err
	}
}

func makeFakeCmd(fakeCmd *fakeexec.FakeCmd, cmd string, args ...string) fakeexec.FakeCommandAction {
	c := cmd
	a := args
	return func(cmd string, args ...string) exec.Cmd {
		command := fakeexec.InitFakeCmd(fakeCmd, c, a...)
		return command
	}
}

func newRepository(name, cloneURL string) *github.Repository {
	return &github.Repository{
		Name:     &name,
		CloneURL: &cloneURL,
	}
}

func TestGetResult(t *testing.T) {
	cases := []struct {
		name           string
		repo           *github.Repository
		token          string
		scanResultPath string
		resultContent  string
		scanError      error
		want           *trivytypes.Report
		wantErr        bool
	}{
		{
			name:           "OK",
			repo:           newRepository("test", ""),
			scanResultPath: "result.json",
			resultContent: `{
"ArtifactName": "ArtifactName",
"ArtifactType": "repository",
"Results": [
	{
	"Target": "Target",
	"Class": "lang-pkgs",
	"Type": "type",
	"Vulnerabilities": []
	}
]
}`,
			want: &trivytypes.Report{
				ArtifactName: "ArtifactName",
				ArtifactType: "repository",
				Results: []trivytypes.Result{
					{
						Target: "Target",
						Class:  "lang-pkgs",
						Type:   "type",
					},
				},
			},
		},
		{
			name:           "NG scan error",
			repo:           newRepository("test", ""),
			scanResultPath: `scan_error.json`,
			resultContent:  ``,
			scanError:      errors.New("something error"),
			want:           &trivytypes.Report{},
			wantErr:        true,
		},
		{
			name:           "NG json unmarshal error",
			repo:           newRepository("test", ""),
			scanResultPath: `invalid_format.json`,
			resultContent:  `invalid format`,
			scanError:      nil,
			want:           &trivytypes.Report{},
			wantErr:        true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			trivyClient := &fakeTrivyClient{err: c.scanError}
			client := dependencyClient{
				trivy: trivyClient,
			}
			// create test data
			f, err := os.CreateTemp("", c.scanResultPath)
			if err != nil {
				t.Fatalf("Failed to create test result file. err: %+v", err)
			}
			_, err = f.Write([]byte(c.resultContent))
			if err != nil {
				t.Fatalf("Failed to write test result file. err: %+v", err)
			}
			err = f.Close()
			if err != nil {
				t.Fatalf("Failed to close test result file. err: %+v", err)
			}
			defer os.Remove(f.Name())
			got, err := client.getResult(ctx, c.repo, c.token, f.Name())
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}
			if reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected not matching: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestScan(t *testing.T) {
	cases := []struct {
		name       string
		repo       *github.Repository
		token      string
		filePath   string
		execScript ExecArgs
		scanResult string
		scanError  error
		want       []byte
		wantErr    bool
	}{
		{
			name:       "OK",
			wantErr:    false,
			repo:       newRepository("", ""),
			execScript: ExecArgs{"/usr/local/bin/trivy", []string{"repository", "--security-checks", "vuln", "--output", "path", "--format", "json", "url"}, "", nil},
		},
		{
			name:       "NG scan error",
			wantErr:    true,
			repo:       newRepository("", ""),
			execScript: ExecArgs{"/usr/local/bin/trivy", []string{"repository", "--security-checks", "vuln", "--output", "path", "--format", "json", "url"}, "", errors.New("something occurs")},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			fakeExec := &fakeexec.FakeExec{}
			fakeCmd := &fakeexec.FakeCmd{}
			cmdAction := makeFakeCmd(fakeCmd, c.execScript.command, c.execScript.args...)
			outputAction := makeFakeOutput(c.execScript.output, c.execScript.err)
			fakeCmd.RunScript = append(fakeCmd.RunScript, outputAction)
			var stderr bytes.Buffer
			var stdout bytes.Buffer
			fakeCmd.Stdout = &stdout
			fakeCmd.Stderr = &stderr
			fakeExec.CommandScript = append(fakeExec.CommandScript, cmdAction)

			client := newtrivyClient("trivyPath", fakeExec)
			err := client.scan(ctx, c.repo, c.token, c.filePath)
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}
		})
	}
}

type ExecArgs struct {
	command string
	args    []string
	output  string
	err     error
}
