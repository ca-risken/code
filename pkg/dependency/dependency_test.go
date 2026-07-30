package dependency

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/ca-risken/common/pkg/logging"
	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
	"k8s.io/utils/exec"
	fakeexec "k8s.io/utils/exec/testing"
)

type fakeTrivyClient struct {
	err error
}

func (f *fakeTrivyClient) Scan(ctx context.Context, cloneURL, token, filePath string, retryRepositoryNotFound bool) error {
	return f.err
}

func makeFakeOutput(output, errorOutput string, err error) fakeexec.FakeAction {
	o := output
	e := errorOutput
	return func() ([]byte, []byte, error) {
		return []byte(o), []byte(e), err
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

func TestGetResult(t *testing.T) {
	cases := []struct {
		name           string
		cloneURL       string
		token          string
		scanResultPath string
		resultContent  string
		scanError      error
		want           *trivytypes.Report
		wantErr        bool
	}{
		{
			name:           "OK",
			cloneURL:       "test",
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
			cloneURL:       "test",
			scanResultPath: `scan_error.json`,
			resultContent:  ``,
			scanError:      errors.New("something error"),
			want:           &trivytypes.Report{},
			wantErr:        true,
		},
		{
			name:           "NG json unmarshal error",
			cloneURL:       "test",
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
			got, err := client.getResult(ctx, c.cloneURL, c.token, f.Name(), false)
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
		name           string
		cloneURL       string
		token          string
		filePath       string
		execScript     ExecArgs
		scanResult     string
		scanError      error
		wantErrContain string
		wantErrExclude string
		want           []byte
		wantErr        bool
	}{
		{
			name:     "OK",
			wantErr:  false,
			cloneURL: "test",
			execScript: ExecArgs{
				command: "/usr/local/bin/trivy",
				args:    []string{"repository", "--security-checks", "vuln", "--output", "path", "--format", "json", "url"},
			},
		},
		{
			name:           "NG scan error",
			wantErr:        true,
			wantErrContain: "something occurs",
			wantErrExclude: "sensitive credential diagnostic",
			cloneURL:       "test",
			execScript: ExecArgs{
				command:     "/usr/local/bin/trivy",
				args:        []string{"repository", "--security-checks", "vuln", "--output", "path", "--format", "json", "url"},
				errorOutput: "sensitive credential diagnostic",
				err:         errors.New("something occurs"),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			fakeExec := &fakeexec.FakeExec{}
			fakeCmd := &fakeexec.FakeCmd{}
			cmdAction := makeFakeCmd(fakeCmd, c.execScript.command, c.execScript.args...)
			outputAction := makeFakeOutput(c.execScript.output, c.execScript.errorOutput, c.execScript.err)
			fakeCmd.RunScript = append(fakeCmd.RunScript, outputAction)
			var stderr bytes.Buffer
			var stdout bytes.Buffer
			fakeCmd.Stdout = &stdout
			fakeCmd.Stderr = &stderr
			fakeExec.CommandScript = append(fakeExec.CommandScript, cmdAction)

			retryNum := uint64(0)
			client := newTrivyClient("trivyPath", fakeExec, &retryNum, logging.NewLogger())
			err := client.Scan(ctx, c.cloneURL, c.token, c.filePath, false)
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}
			if c.wantErrContain != "" && (err == nil || !strings.Contains(err.Error(), c.wantErrContain)) {
				t.Fatalf("error = %v, want it to contain %q", err, c.wantErrContain)
			}
			if c.wantErrExclude != "" && err != nil && strings.Contains(err.Error(), c.wantErrExclude) {
				t.Fatalf("error = %v, want it not to contain %q", err, c.wantErrExclude)
			}
		})
	}
}

func TestScanGitHubAppRepositoryNotFoundRetry(t *testing.T) {
	cases := []struct {
		name         string
		errorOutputs []string
		runErrors    []error
		wantErr      bool
		wantAttempts int
		wantRepoErr  bool
	}{
		{
			name:         "recovers after repository not found",
			errorOutputs: []string{"Repository not found", "Repository not found", ""},
			runErrors:    []error{errors.New("exit 1"), errors.New("exit 1"), nil},
			wantAttempts: 3,
		},
		{
			name:         "exhausts repository not found retries",
			errorOutputs: []string{"Repository not found", "Repository not found", "Repository not found", "Repository not found"},
			runErrors:    []error{errors.New("exit 1"), errors.New("exit 1"), errors.New("exit 1"), errors.New("exit 1")},
			wantErr:      true,
			wantAttempts: 4,
			wantRepoErr:  true,
		},
		{
			name:         "keeps short retries for other errors",
			errorOutputs: []string{"scanner initialization failed", "scanner initialization failed", "scanner initialization failed", "scanner initialization failed"},
			runErrors:    []error{errors.New("exit 1"), errors.New("exit 1"), errors.New("exit 1"), errors.New("exit 1")},
			wantErr:      true,
			wantAttempts: 4,
		},
		{
			name:         "switches to repository not found without resetting retry budget",
			errorOutputs: []string{"scanner initialization failed", "Repository not found", "Repository not found", "Repository not found"},
			runErrors:    []error{errors.New("exit 1"), errors.New("exit 1"), errors.New("exit 1"), errors.New("exit 1")},
			wantErr:      true,
			wantAttempts: 4,
			wantRepoErr:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeExec := &fakeexec.FakeExec{}
			fakeCmd := &fakeexec.FakeCmd{}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			fakeCmd.Stdout = &stdout
			fakeCmd.Stderr = &stderr
			for i := range c.runErrors {
				fakeExec.CommandScript = append(fakeExec.CommandScript, makeFakeCmd(fakeCmd, "trivy"))
				fakeCmd.RunScript = append(fakeCmd.RunScript, makeFakeOutput("", c.errorOutputs[i], c.runErrors[i]))
			}
			client := newTrivyClient("trivy", fakeExec, nil, logging.NewLogger()).(*trivyClient)
			client.wait = func(context.Context, time.Duration) error { return nil }

			err := client.Scan(context.Background(), "https://github.com/owner/repo.git", "token", filepathForTest(t), true)
			if c.wantErr && err == nil {
				t.Fatal("Scan() error = nil, want error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if got := fakeExec.CommandCalls; got != c.wantAttempts {
				t.Fatalf("Scan() attempts = %d, want %d", got, c.wantAttempts)
			}
			if c.wantRepoErr && !errors.Is(err, gittransport.ErrRepositoryNotFound) {
				t.Fatalf("Scan() error = %v, want repository not found", err)
			}
		})
	}
}

func TestScanRetryPreparationFailureIsNotRepositoryNotFound(t *testing.T) {
	fakeExec := &fakeexec.FakeExec{}
	fakeCmd := &fakeexec.FakeCmd{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	fakeCmd.Stdout = &stdout
	fakeCmd.Stderr = &stderr
	fakeExec.CommandScript = append(fakeExec.CommandScript, makeFakeCmd(fakeCmd, "trivy"))
	fakeCmd.RunScript = append(fakeCmd.RunScript, makeFakeOutput("", "Repository not found", errors.New("exit 1")))

	client := newTrivyClient("trivy", fakeExec, nil, logging.NewLogger()).(*trivyClient)
	client.wait = func(context.Context, time.Duration) error { return context.Canceled }

	err := client.Scan(context.Background(), "https://github.com/owner/repo.git", "token", filepathForTest(t), true)
	if errors.Is(err, gittransport.ErrRepositoryNotFound) {
		t.Fatalf("Scan() error = %v, do not want repository not found classification", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan() error = %v, want context canceled", err)
	}
}

func TestScanClassifiesRepositoryNotFound(t *testing.T) {
	trivyErr := errors.New("trivy exited")
	cases := []struct {
		name        string
		errorOutput string
		wantRepoErr bool
	}{
		{
			name:        "classifies strict repository not found line",
			errorOutput: "remote: Repository not found.",
			wantRepoErr: true,
		},
		{
			name:        "does not verify unrelated trivy error",
			errorOutput: "scanner initialization failed",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeExec := &fakeexec.FakeExec{}
			fakeCmd := &fakeexec.FakeCmd{}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			fakeCmd.Stdout = &stdout
			fakeCmd.Stderr = &stderr
			fakeExec.CommandScript = append(fakeExec.CommandScript, makeFakeCmd(fakeCmd, "trivy"))
			fakeCmd.RunScript = append(fakeCmd.RunScript, makeFakeOutput("", c.errorOutput, trivyErr))

			retryNum := uint64(0)
			client := newTrivyClient("trivy", fakeExec, &retryNum, logging.NewLogger()).(*trivyClient)

			err := client.Scan(context.Background(), "https://github.com/owner/repo.git", "token", filepathForTest(t), true)
			if err == nil {
				t.Fatal("Scan() error = nil, want error")
			}
			if got := errors.Is(err, gittransport.ErrRepositoryNotFound); got != c.wantRepoErr {
				t.Fatalf("Scan() repository not found = %v, want %v; err=%v", got, c.wantRepoErr, err)
			}
			if !errors.Is(err, trivyErr) {
				t.Fatalf("Scan() error = %v, want original trivy error", err)
			}
		})
	}
}

func TestResetTrivyOutput(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(*testing.T) string
		wantErr bool
	}{
		{
			name: "truncates existing file and keeps private permissions",
			prepare: func(t *testing.T) string {
				path := filepathForTest(t)
				if err := os.WriteFile(path, []byte("partial"), 0644); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
				return path
			},
		},
		{
			name: "rejects symlink",
			prepare: func(t *testing.T) string {
				target := filepathForTest(t)
				link := target + "-link"
				if err := os.Symlink(target, link); err != nil {
					t.Fatalf("Symlink() error = %v", err)
				}
				t.Cleanup(func() { os.Remove(link) })
				return link
			},
			wantErr: true,
		},
		{
			name: "recreates missing file",
			prepare: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing.json")
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := c.prepare(t)
			err := resetTrivyOutput(path)
			if c.wantErr {
				if err == nil {
					t.Fatal("resetTrivyOutput() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("resetTrivyOutput() error = %v", err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat() error = %v", err)
			}
			if info.Size() != 0 {
				t.Fatalf("resetTrivyOutput() size = %d, want 0", info.Size())
			}
			if got := info.Mode().Perm(); got != 0600 {
				t.Fatalf("resetTrivyOutput() permissions = %o, want 600", got)
			}
		})
	}
}

func TestIsRepositoryNotFoundOutput(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "exact message", output: "Repository not found.", want: true},
		{name: "prefixed message", output: "failed to clone: Repository not found.", want: true},
		{name: "multiple lines", output: "diagnostic\nremote: Repository not found.\n", want: true},
		{name: "phrase embedded in diagnostic", output: "repository not found while parsing a local file path", want: false},
		{name: "unrelated", output: "scanner initialization failed", want: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isRepositoryNotFoundOutput(c.output); got != c.want {
				t.Fatalf("isRepositoryNotFoundOutput(%q) = %v, want %v", c.output, got, c.want)
			}
		})
	}
}

func filepathForTest(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "dependency-retry-*.json")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })
	return path
}

type ExecArgs struct {
	command     string
	args        []string
	output      string
	errorOutput string
	err         error
}
