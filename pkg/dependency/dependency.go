package dependency

import (
	"bytes"
	"context"
	"encoding/json"

	"fmt"
	"os"
	"time"

	"k8s.io/utils/exec"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/cenkalti/backoff/v4"
)

const RETRY_NUM uint64 = 3

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
	Scan(ctx context.Context, cloneURL, token, outputPath string) error
}

type trivyClient struct {
	trivyPath string
	exec      exec.Interface
	retryer   backoff.BackOff
	logger    logging.Logger
}

func newTrivyClient(trivyPath string, exec exec.Interface, retryNum *uint64, l logging.Logger) trivyScanner {
	retry := RETRY_NUM
	if retryNum != nil {
		retry = *retryNum
	}
	return &trivyClient{
		trivyPath: trivyPath,
		exec:      exec,
		retryer:   backoff.WithMaxRetries(backoff.NewExponentialBackOff(), retry),
		logger:    l,
	}
}

func newDependencyClient(ctx context.Context, conf *dependencyConfig, l logging.Logger) dependencyServiceClient {
	return &dependencyClient{
		config: *conf,
		trivy:  newTrivyClient(conf.trivyPath, exec.New(), nil, l),
	}
}

func (d *dependencyClient) getResult(ctx context.Context, cloneURL, token, outputPath string) (*trivytypes.Report, error) {
	defer os.Remove(outputPath)
	err := d.trivy.Scan(ctx, cloneURL, token, outputPath)
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

func (t *trivyClient) Scan(ctx context.Context, cloneURL, token string, outputPath string) error {
	operation := func() error {
		return t.scan(ctx, cloneURL, token, outputPath)
	}
	return backoff.RetryNotify(operation, t.retryer, t.newRetryLogger(ctx, "trivy scan"))
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
		return fmt.Errorf("failed to execute trivy: err=%w, cloneURL=%s", err, cloneURL)
	}
	return nil
}

func (t *trivyClient) newRetryLogger(ctx context.Context, funcName string) func(error, time.Duration) {
	return func(err error, ti time.Duration) {
		t.logger.Warnf(ctx, "[RetryLogger] %s error: duration=%+v, err=%+v", funcName, ti, err)
	}
}
