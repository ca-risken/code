package dependency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/utils/exec"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/cenkalti/backoff/v4"
	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
)

const RETRY_NUM uint64 = 3

var gitHubAppRepositoryNotFoundRetryIntervals = []time.Duration{
	3 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

type dependencyServiceClient interface {
	getResult(ctx context.Context, cloneURL, token, outputPath string, retryRepositoryNotFound bool) (*trivytypes.Report, error)
}

type dependencyConfig struct {
	trivyPath string
}

type dependencyClient struct {
	config dependencyConfig
	trivy  trivyScanner
}

type trivyScanner interface {
	Scan(ctx context.Context, cloneURL, token, outputPath string, retryRepositoryNotFound bool) error
}

type trivyClient struct {
	trivyPath string
	exec      exec.Interface
	retryNum  uint64
	logger    logging.Logger
	wait      func(context.Context, time.Duration) error
}

func newTrivyClient(trivyPath string, exec exec.Interface, retryNum *uint64, l logging.Logger) trivyScanner {
	retry := RETRY_NUM
	if retryNum != nil {
		retry = *retryNum
	}
	return &trivyClient{
		trivyPath: trivyPath,
		exec:      exec,
		retryNum:  retry,
		logger:    l,
		wait:      waitForTrivyRetry,
	}
}

func newDependencyClient(conf *dependencyConfig, l logging.Logger) dependencyServiceClient {
	return &dependencyClient{
		config: *conf,
		trivy:  newTrivyClient(conf.trivyPath, exec.New(), nil, l),
	}
}

func (d *dependencyClient) getResult(ctx context.Context, cloneURL, token, outputPath string, retryRepositoryNotFound bool) (*trivytypes.Report, error) {
	defer os.Remove(outputPath)
	err := d.trivy.Scan(ctx, cloneURL, token, outputPath, retryRepositoryNotFound)
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

func waitForTrivyRetry(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (t *trivyClient) Scan(ctx context.Context, cloneURL, token string, outputPath string, retryRepositoryNotFound bool) error {
	err := t.scan(ctx, cloneURL, token, outputPath)
	if err == nil {
		return nil
	}
	return t.retry(ctx, cloneURL, token, outputPath, err, retryRepositoryNotFound)
}

func (t *trivyClient) retry(ctx context.Context, cloneURL, token, outputPath string, initialErr error, retryRepositoryNotFound bool) error {
	err := initialErr
	retryer := backoff.NewExponentialBackOff()
	retryer.Reset()
	repositoryNotFoundRetryIndex := 0
	for range t.retryNum {
		var interval time.Duration
		if retryRepositoryNotFound && errors.Is(err, gittransport.ErrRepositoryNotFound) {
			if repositoryNotFoundRetryIndex >= len(gitHubAppRepositoryNotFoundRetryIntervals) {
				break
			}
			interval = gitHubAppRepositoryNotFoundRetryIntervals[repositoryNotFoundRetryIndex]
			repositoryNotFoundRetryIndex++
		} else {
			interval = retryer.NextBackOff()
			if interval == backoff.Stop {
				break
			}
		}
		t.newRetryLogger(ctx, "trivy scan")(err, interval)
		if waitErr := t.wait(ctx, interval); waitErr != nil {
			return errors.Join(err, waitErr)
		}
		if resetErr := resetTrivyOutput(outputPath); resetErr != nil {
			return errors.Join(err, resetErr)
		}
		err = t.scan(ctx, cloneURL, token, outputPath)
		if err == nil {
			return nil
		}
	}
	return err
}

func resetTrivyOutput(outputPath string) error {
	info, err := os.Lstat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to inspect trivy output %s: %w", outputPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to reset symlinked trivy output: %s", outputPath)
	}
	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to reset trivy output %s: %w", outputPath, err)
	}
	if err := file.Chmod(0600); err != nil {
		return errors.Join(
			fmt.Errorf("failed to secure trivy output %s: %w", outputPath, err),
			file.Close(),
		)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close trivy output %s: %w", outputPath, err)
	}
	return nil
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
		if isRepositoryNotFoundOutput(stderr.String()) {
			return fmt.Errorf("failed to execute trivy: err=%v, cloneURL=%s: %w", err, cloneURL, gittransport.ErrRepositoryNotFound)
		}
		return fmt.Errorf("failed to execute trivy: err=%w, cloneURL=%s", err, cloneURL)
	}
	return nil
}

func isRepositoryNotFoundOutput(output string) bool {
	for _, line := range strings.Split(strings.ToLower(output), "\n") {
		normalized := strings.TrimSuffix(strings.TrimSpace(line), ".")
		if normalized == "repository not found" || strings.HasSuffix(normalized, ": repository not found") {
			return true
		}
	}
	return false
}

func (t *trivyClient) newRetryLogger(ctx context.Context, funcName string) func(error, time.Duration) {
	return func(err error, ti time.Duration) {
		t.logger.Warnf(ctx, "[RetryLogger] %s error: duration=%+v, err=%+v", funcName, ti, err)
	}
}
