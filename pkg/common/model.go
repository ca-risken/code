package common

import "time"

// CodeDataSource entity
type CodeDataSource struct {
	CodeDataSourceID uint32
	Name             string
	Description      string
	MaxScore         float32
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// CodeGitleaks entity
type CodeGitleaks struct {
	GitleaksID          uint32
	CodeDataSourceID    uint32
	Name                string
	ProjectID           uint32
	Type                string
	TargetResource      string
	RepositoryPattern   string
	GithubUser          string
	PersonalAccessToken string
	GitleaksConfig      string
	Status              string
	StatusDetail        string
	ScanAt              time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
