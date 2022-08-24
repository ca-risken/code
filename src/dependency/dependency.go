package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-github/v44/github"
)

type dependencyServiceClient interface {
	scan(ctx context.Context, repo *github.Repository, token string) (*trivytypes.Report, error)
}

type dependencyConfig struct {
	githubDefaultToken string
	trivyPath          string
}

type dependencyClient struct {
	config dependencyConfig
}

func newDependencyClient(ctx context.Context, conf *dependencyConfig) dependencyServiceClient {
	return &dependencyClient{
		config: *conf,
	}
}

func (d *dependencyClient) scan(ctx context.Context, repo *github.Repository, token string) (*trivytypes.Report, error) {
	now := time.Now().Unix()
	filePath := fmt.Sprintf("%s_%v.json", *repo.Name, now)
	trivyPath := fmt.Sprintf(d.config.trivyPath)
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	// option --security-checks vuln: skip secret scanning
	cmd := exec.CommandContext(ctx, trivyPath, "repository", "--security-checks", "vuln", "--output", filePath, "--format", "json", *repo.CloneURL)
	cmd.Env = []string{fmt.Sprintf("GITHUB_TOKEN=%s", token)}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		appLogger.Errorf(ctx, "Failed to execute trivy. error: %+v, stderr: %v", err, stderr.String())
		return nil, err
	}

	bytes, err := readAndDeleteFile(filePath)
	if err != nil {
		return nil, err
	}
	var dependency trivytypes.Report
	if err = json.Unmarshal(bytes, &dependency); err != nil {
		appLogger.Errorf(ctx, "Failed to unmarshal result. error: %v", err)
		return nil, err
	}
	return &dependency, nil
}

func readAndDeleteFile(fileName string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(fileName); err != nil {
		return nil, err
	}
	return bytes, nil
}
