package main

import (
	"context"
	"fmt"

	"github.com/CyberAgent/mimosa-code/pkg/common"
	"github.com/CyberAgent/mimosa-code/proto/code"
	mimosasql "github.com/CyberAgent/mimosa-common/pkg/database/sql"
	"github.com/kelseyhightower/envconfig"
	"github.com/vikyd/zero"
	"gorm.io/gorm"
)

type codeRepoInterface interface {
	// code_data_source
	ListDataSource(ctx context.Context, codeDataSourceID uint32, name string) (*[]common.CodeDataSource, error)

	// code_gitleaks
	ListGitleaks(ctx context.Context, projectID, codeDataSourceID, gitleaksID uint32) (*[]common.CodeGitleaks, error)
	UpsertGitleaks(ctx context.Context, data *code.GitleaksForUpsert) (*common.CodeGitleaks, error)
	DeleteGitleaks(ctx context.Context, projectID uint32, gitleaksID uint32) error
	GetGitleaks(ctx context.Context, projectID, gitleaksID uint32) (*common.CodeGitleaks, error)

	// code_enterprise_org
	ListEnterpriseOrg(ctx context.Context, projectID, gitleaksID uint32) (*[]common.CodeEnterpriseOrg, error)
	UpsertEnterpriseOrg(ctx context.Context, data *code.EnterpriseOrgForUpsert) (*common.CodeEnterpriseOrg, error)
	DeleteEnterpriseOrg(ctx context.Context, projectID, gitleaksID uint32, login string) error
}

type codeRepository struct {
	MasterDB *gorm.DB
	SlaveDB  *gorm.DB
}

func newCodeRepository() codeRepoInterface {
	repo := codeRepository{}
	repo.MasterDB = initDB(true)
	repo.SlaveDB = initDB(false)
	return &repo
}

type dbConfig struct {
	MasterHost     string `split_words:"true" required:"true"`
	MasterUser     string `split_words:"true" required:"true"`
	MasterPassword string `split_words:"true" required:"true"`
	SlaveHost      string `split_words:"true"`
	SlaveUser      string `split_words:"true"`
	SlavePassword  string `split_words:"true"`

	Schema  string `required:"true"`
	Port    int    `required:"true"`
	LogMode bool   `split_words:"true" default:"false"`
}

func initDB(isMaster bool) *gorm.DB {
	conf := &dbConfig{}
	if err := envconfig.Process("DB", conf); err != nil {
		appLogger.Fatalf("Failed to load DB config. err: %+v", err)
	}

	var user, pass, host string
	if isMaster {
		user = conf.MasterUser
		pass = conf.MasterPassword
		host = conf.MasterHost
	} else {
		user = conf.SlaveUser
		pass = conf.SlavePassword
		host = conf.SlaveHost
	}

	dsn := fmt.Sprintf("%s:%s@tcp([%s]:%d)/%s?charset=utf8mb4&interpolateParams=true&parseTime=true&loc=Local",
		user, pass, host, conf.Port, conf.Schema)
	db, err := mimosasql.Open(dsn, conf.LogMode)
	if err != nil {
		appLogger.Fatalf("Failed to open DB. isMaster: %t, err: %+v", isMaster, err)
		return nil
	}
	appLogger.Infof("Connected to Database. isMaster: %t", isMaster)
	return db
}

func convertZeroValueToNull(input interface{}) interface{} {
	if zero.IsZeroVal(input) {
		return gorm.Expr("NULL")
	}
	return input
}
