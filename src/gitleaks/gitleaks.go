package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"
)

type gitleaksServiceClient interface {
	scanRepository(ctx context.Context, token string, findings *repositoryFinding) error
}

type gitleaksClient struct {
	defaultToken          string
	limitRepositorySizeKb int
}

func newGitleaksClient() gitleaksServiceClient {
	var conf gihubConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Could not read githubConfig. err: %+v", err)
	}
	return &gitleaksClient{
		defaultToken:          conf.GithubDefaultToken,
		limitRepositorySizeKb: conf.LimitRepositorySizeKb,
	}
}

type leakFinding struct {
	DataSourceID string `json:"data_source_id"`

	Line       string    `json:"line,omitempty"`
	LineNumber int       `json:"lineNumber,omitempty"`
	Offender   string    `json:"offender,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	Repo       string    `json:"repo,omitempty"`
	RepoURL    string    `json:"repoURL,omitempty"`
	LeakURL    string    `json:"leakURL"`
	Rule       string    `json:"rule,omitempty"`
	Message    string    `json:"commitMessage,omitempty"`
	Author     string    `json:"author,omitempty"`
	Email      string    `json:"email,omitempty"`
	File       string    `json:"file,omitempty"`
	Date       time.Time `json:"date,omitempty"`
	Tags       string    `json:"tags,omitempty"`
}

func (l *leakFinding) generateDataSourceID() {
	hash := sha256.Sum256([]byte(l.Repo + l.Commit + l.Offender + l.File + l.Line + fmt.Sprint(l.LineNumber)))
	l.DataSourceID = hex.EncodeToString(hash[:])
}

func (g *gitleaksClient) scanRepository(ctx context.Context, token string, f *repositoryFinding) error {
	if g.skipScan(f) {
		f.SkipScan = true
		return nil
	}
	opts := options.Options{
		RepoURL:     *f.CloneURL,
		AccessToken: getToken(token, g.defaultToken),
		Verbose:     true,
		// Threads:     1,
		// Depth: 1,
		Debug: true,
	}
	cfg, err := config.NewConfig(opts)
	if err != nil {
		return err
	}
	appLogger.Infof("Start scan gitleaks: repository=%s, size=%d(kb)", *f.FullName, *f.Size)
	scanner, err := scan.NewScanner(opts, cfg)
	if err != nil {
		return err
	}
	scannerReport, err := scanner.Scan()
	if err != nil {
		// A scanning error occurred, but continue scanning the other repositories...
		appLogger.Errorf("Failed to scan `Gitleaks`: repository=%s, err=%+v", *f.FullName, err)
		return nil
	}
	for _, leak := range scannerReport.Leaks {
		f.LeakFindings = append(f.LeakFindings, &leakFinding{
			Line:       cutString(leak.Line, 200),
			LineNumber: leak.LineNumber,
			Offender:   leak.Offender,
			Commit:     leak.Commit,
			Repo:       leak.Repo,
			RepoURL:    leak.RepoURL,
			LeakURL:    leak.LeakURL,
			Rule:       leak.Rule,
			Message:    leak.Message,
			Author:     leak.Author,
			Email:      leak.Email,
			File:       leak.File,
			Date:       leak.Date,
			Tags:       leak.Tags,
		})
	}
	return nil
}

func (g *gitleaksClient) skipScan(repo *repositoryFinding) bool {
	// Check the repo status
	if repo == nil || *repo.Archived || *repo.Fork || *repo.Disabled {
		appLogger.Infof("Skip scan for %s, because repository is archived or disabled or fork repo.", *repo.FullName)
		return true
	}

	// Hard limit size
	if *repo.Size > g.limitRepositorySizeKb {
		appLogger.Warnf("Skip scan for %s, because repository is too big size, limit=%dkb, size(kb)=%dkb", *repo.FullName, g.limitRepositorySizeKb, *repo.Size)
		return true
	}

	// HTTP OK?
	resp, err := http.Get(*repo.CloneURL)
	if err != nil {
		appLogger.Warnf("Skip scan for %s, because failed to http request, clone_url=%s, err=%+v", *repo.FullName, *repo.CloneURL, err)
		return true
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		appLogger.Warnf("Skip scan for %s, because failed to http response error, status=%d, clone_url=%s", *repo.FullName, resp.StatusCode, *repo.CloneURL)
		return true
	}

	// Check coparing pushedAt and lastScanedAt
	if repo.alreadyScaned() {
		appLogger.Infof("Skip scan for %s, because the repository was already scaned.", *repo.FullName)
		return true
	}
	return false
}
