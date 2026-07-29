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
	if retryRepositoryNotFound && errors.Is(err, gittransport.ErrRepositoryNotFound) {
		return t.retryRepositoryNotFound(ctx, cloneURL, token, outputPath, err)
	}
	return t.retryWithExponentialBackOff(ctx, cloneURL, token, outputPath, err, retryRepositoryNotFound)
}

func (t *trivyClient) retryRepositoryNotFound(ctx context.Context, cloneURL, token, outputPath string, initialErr error) error {
	err := initialErr
	for _, interval := range gitHubAppRepositoryNotFoundRetryIntervals {
		t.newRetryLogger(ctx, "trivy scan")(err, interval)
		if waitErr := t.wait(ctx, interval); waitErr != nil {
			return waitErr
		}
		if cleanErr := cleanTrivyOutput(outputPath); cleanErr != nil {
			return cleanErr
		}
		err = t.scan(ctx, cloneURL, token, outputPath)
		if err == nil {
			return nil
		}
		if !errors.Is(err, gittransport.ErrRepositoryNotFound) {
			return err
		}
	}
	return err
}

func (t *trivyClient) retryWithExponentialBackOff(ctx context.Context, cloneURL, token, outputPath string, initialErr error, retryRepositoryNotFound bool) error {
	err := initialErr
	retryer := backoff.NewExponentialBackOff()
	retryer.Reset()
	for range t.retryNum {
		interval := retryer.NextBackOff()
		t.newRetryLogger(ctx, "trivy scan")(err, interval)
		if waitErr := t.wait(ctx, interval); waitErr != nil {
			return waitErr
		}
		if cleanErr := cleanTrivyOutput(outputPath); cleanErr != nil {
			return cleanErr
		}
		err = t.scan(ctx, cloneURL, token, outputPath)
		if err == nil {
			return nil
		}
		if retryRepositoryNotFound && errors.Is(err, gittransport.ErrRepositoryNotFound) {
			return t.retryRepositoryNotFound(ctx, cloneURL, token, outputPath, err)
		}
	}
	return err
}

func cleanTrivyOutput(outputPath string) error {
	if err := os.Remove(outputPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clean trivy output %s: %w", outputPath, err)
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
		if strings.Contains(strings.ToLower(stderr.String()), "repository not found") {
			return fmt.Errorf("failed to execute trivy: err=%v, cloneURL=%s, stderr=%s: %w", err, cloneURL, stderr.String(), gittransport.ErrRepositoryNotFound)
		}
		return fmt.Errorf("failed to execute trivy: err=%w, cloneURL=%s, stderr=%s", err, cloneURL, stderr.String())
	}
	return nil
}

func (t *trivyClient) newRetryLogger(ctx context.Context, funcName string) func(error, time.Duration) {
	return func(err error, ti time.Duration) {
		t.logger.Warnf(ctx, "[RetryLogger] %s error: duration=%+v, err=%+v", funcName, ti, err)
	}
}
