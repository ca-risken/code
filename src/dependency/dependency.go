package main

import (
	"bytes"
	"context"
	"encoding/json"

	"fmt"
	"os"
	"time"

	"k8s.io/utils/exec"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
)

type dependencyServiceClient interface {
	getResult(ctx context.Context, cloneURL, token, outputPath string) (*trivytypes.Report, error)
}

type dependencyConfig struct {
	githubDefaultToken string
	trivyPath          string
}

type dependencyClient struct {
	config dependencyConfig
	trivy  trivyScanner
}

type trivyScanner interface {
	scan(ctx context.Context, cloneURL, token, outputPath string) error
}

type trivyError struct {
	stderr string
	err    error
}

func (e *trivyError) Error() string {
	return fmt.Sprintf("trivy error: %v, stderr: %s", e.err, string(e.stderr))
}

func (e *trivyError) Unwrap() error {
	return e.err
}

type trivyClient struct {
	trivyPath string
	exec      exec.Interface
}

func newTrivyClient(trivyPath string, exec exec.Interface) trivyScanner {
	return &trivyClient{
		trivyPath: trivyPath,
		exec:      exec,
	}
}

func newDependencyClient(ctx context.Context, conf *dependencyConfig) dependencyServiceClient {
	return &dependencyClient{
		config: *conf,
		trivy:  newTrivyClient(conf.trivyPath, exec.New()),
	}
}

func (d *dependencyClient) getResult(ctx context.Context, cloneURL, token, outputPath string) (*trivytypes.Report, error) {
	defer os.Remove(outputPath)
	err := d.trivy.scan(ctx, cloneURL, token, outputPath)
	if err != nil {
		return nil, err
	}

	bytes, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, err
	}

	var dependency trivytypes.Report
	if err = json.Unmarshal(bytes, &dependency); err != nil {
		return nil, err
	}
	return &dependency, nil
}

func (t *trivyClient) scan(ctx context.Context, cloneURL, token string, outputPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()

	//	option --security-checks vuln: skip secret scanning
	cmd := t.exec.CommandContext(ctx, t.trivyPath, "repository", "--security-checks", "vuln", "--output", outputPath, "--format", "json", cloneURL)
	cmd.SetEnv([]string{fmt.Sprintf("GITHUB_TOKEN=%s", token)})
	var stderr bytes.Buffer
	cmd.SetStderr(&stderr)
	err := cmd.Run()
	if err != nil {
		return &trivyError{stderr: stderr.String(), err: err}
	}
	return nil
}
