package main

import (
	"context"
	"fmt"
	"time"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type gitleaksServiceClient interface {
	scan(ctx context.Context, source string, duration *scanDuration) ([]report.Finding, error)
}

type gitleaksConfig struct {
	githubDefaultToken string
	redact             bool
}

type gitleaksClient struct {
	config gitleaksConfig
}

func newGitleaksClient(ctx context.Context, conf *gitleaksConfig) gitleaksServiceClient {
	return &gitleaksClient{
		config: *conf,
	}
}

func (g *gitleaksClient) scan(ctx context.Context, source string, duration *scanDuration) ([]report.Finding, error) {
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize detector: %w", err)
	}
	d.Redact = g.config.redact

	logOps := "--all --date=local"
	timeformat := "2006-01-02T15:04:05-0700"
	if duration != nil {
		d := fmt.Sprintf("--after=%s --until=%s", duration.From.Format(timeformat), duration.To.Format(timeformat))
		logOps = fmt.Sprintf("%s %s", logOps, d)
	}

	findings, err := d.DetectGit(source, logOps, detect.DetectType)
	if err != nil {
		return nil, fmt.Errorf("failed to detect %s: %w", source, err)
	}

	return findings, nil
}

type scanDuration struct {
	From time.Time
	To   time.Time
}

func getScanDuration(from, to time.Time) *scanDuration {
	if to.Unix() < from.Unix() {
		return nil
	}

	toDuration := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, time.Local)
	if from.Day() == to.Day() {
		toDuration = toDuration.AddDate(0, 0, 1)
	}

	if to.Unix() > toDuration.Unix() {
		toDuration = toDuration.AddDate(0, 0, 1)
	}

	return &scanDuration{
		From: time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.Local),
		To:   toDuration,
	}
}
