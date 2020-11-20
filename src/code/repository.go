package main

import (
	"fmt"

	"github.com/CyberAgent/mimosa-code/pkg/common"
	"github.com/CyberAgent/mimosa-code/proto/code"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"github.com/kelseyhightower/envconfig"
)

type codeRepoInterface interface {
	ListDataSource(codeDataSourceID uint32, name string) (*[]common.CodeDataSource, error)
	ListGitleaks(projectID, codeDataSourceID, gitleaksID uint32) (*[]common.CodeGitleaks, error)
	UpsertGitleaks(data *code.GitleaksForUpsert) (*common.CodeGitleaks, error)
	DeleteGitleaks(projectID uint32, gitleaksID uint32) error
	GetGitleaks(projectID, gitleaksID uint32) (*common.CodeGitleaks, error)
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

	db, err := gorm.Open("mysql",
		fmt.Sprintf("%s:%s@tcp([%s]:%d)/%s?charset=utf8mb4&interpolateParams=true&parseTime=true&loc=Local",
			user, pass, host, conf.Port, conf.Schema))
	if err != nil {
		appLogger.Fatalf("Failed to open DB. isMaster: %t, err: %+v", isMaster, err)
		return nil
	}
	db.LogMode(conf.LogMode)
	db.SingularTable(true) // if set this to true, `User`'s default table name will be `user`
	appLogger.Infof("Connected to Database. isMaster: %t", isMaster)
	return db
}
