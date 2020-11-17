package common

import (
	"encoding/json"

	validation "github.com/go-ozzo/ozzo-validation"
)

const (
	// GitleaksDataSource is the specific data_source label for gitleaks
	GitleaksDataSource = "code:gitleaks"
)

// GitleaksQueueMessage is the message for SQS queue
type GitleaksQueueMessage struct {
	GitleaksID uint32 `json:"gitleaks_id"`
	ProjectID  uint32 `json:"project_id"`
}

// Validate is the validation to GuardDutyMessage
func (g *GitleaksQueueMessage) Validate() error {
	return validation.ValidateStruct(g,
		validation.Field(&g.GitleaksID, validation.Required),
		validation.Field(&g.ProjectID, validation.Required),
	)
}

// ParseMessage parse message & validation
func ParseMessage(msg string) (*GitleaksQueueMessage, error) {
	message := &GitleaksQueueMessage{}
	if err := json.Unmarshal([]byte(msg), message); err != nil {
		return nil, err
	}
	if err := message.Validate(); err != nil {
		return nil, err
	}
	return message, nil
}
