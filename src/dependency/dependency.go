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
	"github.com/google/go-github/v44/github"
)

type dependencyServiceClient interface {
	getResult(ctx context.Context, repo *github.Repository, token, filePath string) (*trivytypes.Report, error)
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
	scan(ctx context.Context, repo *github.Repository, token string, filePath string) error
}

type trivyClient struct {
	trivyPath string
	exec      exec.Interface
}

func newtrivyClient(trivyPath string, exec exec.Interface) trivyScanner {
	return &trivyClient{
		trivyPath: trivyPath,
		exec:      exec,
	}
}

func newDependencyClient(ctx context.Context, conf *dependencyConfig) dependencyServiceClient {
	return &dependencyClient{
		config: *conf,
		trivy:  newtrivyClient(conf.trivyPath, exec.New()),
	}
}

func (d *dependencyClient) getResult(ctx context.Context, repo *github.Repository, token, filePath string) (*trivytypes.Report, error) {
	defer os.Remove(filePath)
	err := d.trivy.scan(ctx, repo, token, filePath)
	if err != nil {
		return nil, err
	}

	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var dependency trivytypes.Report
	if err = json.Unmarshal(bytes, &dependency); err != nil {
		return nil, err
	}
	return &dependency, nil
}

func (t *trivyClient) scan(ctx context.Context, repo *github.Repository, token string, filePath string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()

	//	option --security-checks vuln: skip secret scanning
	cmd := t.exec.CommandContext(ctx, t.trivyPath, "repository", "--security-checks", "vuln", "--output", filePath, "--format", "json", *repo.CloneURL)
	cmd.SetEnv([]string{fmt.Sprintf("GITHUB_TOKEN=%s", token)})
	var stderr bytes.Buffer
	cmd.SetStderr(&stderr)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("execute trivy: err: %w", err)
	}
	return nil
}
