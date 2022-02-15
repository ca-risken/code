package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"
)

type gitleaksServiceClient interface {
	scanRepository(ctx context.Context, token string, findings *repositoryFinding) error
}

type GitleaksConfig struct {
	GithubDefaultToken    string
	LimitRepositorySizeKb int
	SeperateScanDays      int
	GitleaksScanThreads   int
	ScanOnMemory          bool
}

type gitleaksClient struct {
	defaultToken          string
	limitRepositorySizeKb int
	seperateScanDays      int
	gitleaksScanThreads   int
	scanOnMemory          bool
}

func newGitleaksClient(conf *GitleaksConfig) gitleaksServiceClient {
	appLogger.Infof(
		"new gitleaks configuration: LIMIT_REPOSITORY_SIZE_KB=%d, SEPERATE_SCAN_DAYS=%d, GITLEAKS_SCAN_THREADS=%d, SCAN_ON_MEMORY=%t",
		conf.LimitRepositorySizeKb, conf.SeperateScanDays, conf.GitleaksScanThreads, conf.ScanOnMemory)
	return &gitleaksClient{
		defaultToken:          conf.GithubDefaultToken,
		limitRepositorySizeKb: conf.LimitRepositorySizeKb,
		seperateScanDays:      conf.SeperateScanDays,
		gitleaksScanThreads:   conf.GitleaksScanThreads,
		scanOnMemory:          conf.ScanOnMemory,
	}
}

type leakFinding struct {
	DataSourceID string `json:"data_source_id"`

	Line       string    `json:"line,omitempty"`
	LineNumber int       `json:"lineNumber,omitempty"`
	Offender   string    `json:"offender,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	Repo       string    `json:"repo,omitempty"`
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
	clonePath, err := generateClonePath(*f.FullName)
	if err != nil {
		return err
	}

	opts := options.Options{
		RepoURL:     *f.CloneURL,
		ClonePath:   clonePath,
		AccessToken: getToken(token, g.defaultToken),
		Verbose:     true,
		Debug:       true,
		Redact:      true,
		Threads:     g.gitleaksScanThreads,
		// Disk:         true,
	}
	if g.scanOnMemory {
		opts.ClonePath = ""
	}
	appLogger.Infof("Start scan repository: fullname=%s, size=%d(kb), createdAt: %v, pushedAt:%v, lastScanedAt: %v",
		*f.FullName, *f.Size, f.CreatedAt, f.PushedAt, f.LastScanedAt)
	durations := g.getScanDuration(f.CreatedAt.Time, f.PushedAt.Time, f.LastScanedAt)
	for idx, duration := range durations {
		if !g.scanOnMemory && idx > 0 {
			//   runtime.GC()
			opts.Path = clonePath // already clone
			opts.ClonePath = ""
		}

		// Set range
		opts.CommitSince = duration.From.Format("2006-01-02")
		opts.CommitUntil = duration.To.Format("2006-01-02")
		cfg, err := config.NewConfig(opts)
		if err != nil {
			return err
		}
		scanner, err := scan.NewScanner(opts, cfg)
		if err != nil {
			return err
		}
		appLogger.Infof("Scan %s %d/%d started... (%s ~ %s)", *f.FullName, idx+1, len(durations), opts.CommitSince, opts.CommitUntil)
		writeMemStats()
		report, err := scanner.Scan()
		if err != nil {
			// A scanning error occurred, but continue scanning the other repositories...
			appLogger.Errorf("Failed to scan `Gitleaks`: repository=%s, err=%+v", *f.FullName, err)
			return nil
		}
		appLogger.Infof("Scan %s %d/%d ended... (%s ~ %s)", *f.FullName, idx+1, len(durations), opts.CommitSince, opts.CommitUntil)
		writeMemStats()
		for _, leak := range report.Leaks {
			f.LeakFindings = append(f.LeakFindings, &leakFinding{
				Line:       cutString(leak.Line, 200),
				LineNumber: leak.LineNumber,
				Offender:   leak.Offender,
				Commit:     leak.Commit,
				Repo:       leak.Repo,
				Rule:       leak.Rule,
				Message:    leak.Message,
				Author:     leak.Author,
				Email:      leak.Email,
				File:       leak.File,
				Date:       leak.Date,
				Tags:       leak.Tags,
			})
		}
		time.Sleep(1 * time.Second)
	}
	return removeDir(clonePath)
}

func (g *gitleaksClient) skipScan(repo *repositoryFinding) bool {
	// Check the repo status
	if repo == nil {
		appLogger.Warnf("Skip scan repository(data not found)")
		return true
	}

	repoName := ""
	if repo.FullName != nil {
		repoName = *repo.FullName
	}
	if repo.Archived != nil && *repo.Archived {
		appLogger.Infof("Skip scan for %s repository(archived)", repoName)
		return true
	}
	if repo.Fork != nil && *repo.Fork {
		appLogger.Infof("Skip scan for %s repository(fork repo)", repoName)
		return true
	}
	if repo.Disabled != nil && *repo.Disabled {
		appLogger.Infof("Skip scan for %s repository(disabled)", repoName)
		return true
	}
	if repo.Size != nil && *repo.Size < 1 {
		appLogger.Infof("Skip scan for %s repository(empty)", repoName)
		return true
	}

	// Hard limit size
	if repo.Size != nil && *repo.Size > g.limitRepositorySizeKb {
		appLogger.Warnf("Skip scan for %s repository(too big size, limit=%dkb, size(kb)=%dkb)", repoName, g.limitRepositorySizeKb, *repo.Size)
		return true
	}

	// Check coparing pushedAt and lastScanedAt
	if repo.alreadyScaned() {
		appLogger.Infof("Skip scan for %s repository(already scaned)", repoName)
		return true
	}
	return false
}

type scanDuration struct {
	From time.Time
	To   time.Time
}

func (g *gitleaksClient) getScanDuration(createdAt, pushedAt, lastScanedAt time.Time) []scanDuration {
	start := createdAt
	if createdAt.Unix() < lastScanedAt.Unix() {
		start = lastScanedAt
	}

	duration := []scanDuration{}
	if g.seperateScanDays < 1 {
		appLogger.Errorf("SeparateScanDays must more than 1, day=%d", g.seperateScanDays)
		return duration
	}

	current := start
	for current.Unix() <= pushedAt.Unix() {
		toDate := current.AddDate(0, 0, g.seperateScanDays)
		duration = append(duration, scanDuration{
			From: time.Date(current.Year(), current.Month(), current.Day(), 0, 0, 0, 0, time.Local), // yyyy/MM/dd 00:00:00
			To:   time.Date(toDate.Year(), toDate.Month(), toDate.Day(), 0, 0, 0, 0, time.Local),    // yyyy/MM/dd+x 00:00:00
		})
		current = toDate
	}
	return duration
}

func generateClonePath(fullName string) (string, error) {
	if fullName == "" {
		return "", errors.New("Failed to generateClonePath: required name.")
	}
	uu, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("Failed to generateClonePath: could not generate UUID, err=%+v", err)
	}
	clonePath := fmt.Sprintf("/tmp/%s-%s", fullName, uu.String())
	if _, err := os.Stat(clonePath); !os.IsNotExist(err) {
		// clonePath is exists
		if err := removeDir(clonePath); err != nil {
			return "", err
		}
	}
	return clonePath, nil
}

func removeDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		appLogger.Warnf("Failed to remove directory, dir=%s, err=%+v", dir, err)
	}
	appLogger.Infof("Success remove directory, dir=%s", dir)
	return nil
}
