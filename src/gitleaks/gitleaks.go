package main

import (
	"context"

	"github.com/google/go-github/v32/github"
	"github.com/kelseyhightower/envconfig"
	"github.com/zricethezav/gitleaks/v6/config"
	"github.com/zricethezav/gitleaks/v6/manager"
	"github.com/zricethezav/gitleaks/v6/options"
	"github.com/zricethezav/gitleaks/v6/scan"
)

type gitleaksServiceClient interface {
	scanRepository(ctx context.Context, repos []*github.Repository) ([]*manager.Leak, error)
}

type gitleaksClient struct{}
type gitleaksConfig struct{}

func newGitleaksClient() gitleaksServiceClient {
	var conf gitleaksConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Could not read gitleaksConfig. err: %+v", err)
	}
	return &gitleaksClient{}
}

func (g *gitleaksClient) scanRepository(ctx context.Context, repos []*github.Repository) ([]*manager.Leak, error) {
	var allLeaks []*manager.Leak
	for _, repo := range repos {
		if skipScan(repo) {
			appLogger.Debugf("Skipp scan gitleaks: repository=%s", *repo.FullName)
			continue
		}
		appLogger.Infof("Start scan gitleaks: repository=%s", *repo.FullName)
		opt := options.Options{Repo: *repo.GitURL}
		cfg, err := config.NewConfig(opt)
		if err != nil {
			return nil, err
		}
		mng, err := manager.NewManager(opt, cfg)
		if err != nil {
			return nil, err
		}
		if err := scan.Run(mng); err != nil {
			return nil, err
		}
		for _, leak := range mng.GetLeaks() {
			allLeaks = append(allLeaks, &leak)
		}
	}
	return allLeaks, nil
}

func skipScan(repo *github.Repository) bool {
	if repo == nil || *repo.Archived || *repo.Fork || *repo.Disabled {
		return true
	}
	return false
}
