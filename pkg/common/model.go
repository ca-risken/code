package common

import "time"

// CodeDataSource entity
type CodeDataSource struct {
	CodeDataSourceID uint32 `gorm:"primary_key"`
	Name             string
	Description      string
	MaxScore         float32
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// CodeGitleaks entity
type CodeGitleaks struct {
	GitleaksID          uint32 `gorm:"primary_key"`
	CodeDataSourceID    uint32
	Name                string
	ProjectID           uint32
	Type                string
	BaseURL             string
	TargetResource      string
	RepositoryPattern   string
	GithubUser          string
	PersonalAccessToken string
	ScanPublic          bool
	ScanInternal        bool
	ScanPrivate         bool
	GitleaksConfig      string
	Status              string
	StatusDetail        string
	ScanAt              time.Time
	ScanSucceededAt     *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// CodeEnterpriseOrg entity
type CodeEnterpriseOrg struct {
	GitleaksID uint32 `gorm:"primary_key"`
	Login      string `gorm:"primary_key"`
	ProjectID  uint32
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
