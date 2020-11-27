package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"time"

	"github.com/CyberAgent/mimosa-code/pkg/common"
	"github.com/CyberAgent/mimosa-code/proto/code"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/kelseyhightower/envconfig"
)

type sqsHandler struct {
	cipherBlock    cipher.Block
	githubClient   githubServiceClient
	gitleaksClient gitleaksServiceClient
	findingClient  finding.FindingServiceClient
	alertClient    alert.AlertServiceClient
	codeClient     code.CodeServiceClient
}

type gitleaksConf struct {
	DataKey string `split_words:"true" required:"true"`
}

func newHandler() *sqsHandler {
	var conf gitleaksConf
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	key := []byte(conf.DataKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	return &sqsHandler{
		cipherBlock:    block,
		githubClient:   newGithubClient(),
		gitleaksClient: newGitleaksClient(),
		findingClient:  newFindingClient(),
		alertClient:    newAlertClient(),
		codeClient:     newCodeClient(),
	}
}

func (s *sqsHandler) HandleMessage(msg *sqs.Message) error {
	msgBody := aws.StringValue(msg.Body)
	appLogger.Infof("got message: %s", msgBody)
	message, err := common.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message: msg=%+v, err=%+v", msg, err)
		return err
	}

	ctx := context.Background()
	// Get saved configuration form codeService
	scanStatus, err := s.getInitScanStatus(ctx, message.ProjectID, message.GitleaksID)
	if err != nil {
		appLogger.Errorf("Failed to get scan status: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
		return err
	}
	decryptedKey, err := common.DecryptWithBase64(&s.cipherBlock, scanStatus.Gitleaks.PersonalAccessToken)
	if err != nil {
		appLogger.Errorf("Failed to decrypted personal access token: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
		return s.updateScanStatusError(ctx, scanStatus, err.Error())
	}

	// Get repositories
	repos, err := s.githubClient.listRepository(ctx, decryptedKey, scanStatus)
	if err != nil {
		appLogger.Errorf("Faild to list repositories: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
		return s.updateScanStatusError(ctx, scanStatus, err.Error())
	}
	appLogger.Debugf("Got repositories, count=%d", len(repos))

	// Scan repository
	leaks, err := s.gitleaksClient.scanRepository(ctx, repos)
	if err != nil {
		appLogger.Errorf("Faild to scan repositories: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
		return s.updateScanStatusError(ctx, scanStatus, err.Error())
	}
	appLogger.Debugf("Got leaks: gitleaks_id=%d, leaks=%+v", message.GitleaksID, leaks)

	// Put finding
	// if err := s.putFindings(ctx, findings); err != nil {
	// 	appLogger.Errorf("Faild to put findngs: AccountID=%+v, err=%+v", message.AccountID, err)
	// 	return s.updateScanStatusError(ctx, &putStatus, err.Error())
	// }
	// if err := s.updateScanStatusSuccess(ctx, &putStatus); err != nil {
	// 	return err
	// }
	return s.analyzeAlert(ctx, message.ProjectID)
}

func (s *sqsHandler) getInitScanStatus(ctx context.Context, projectID, gitleaksID uint32) (*code.PutGitleaksRequest, error) {
	data, err := s.codeClient.ListGitleaks(ctx, &code.ListGitleaksRequest{
		ProjectId:  projectID,
		GitleaksId: gitleaksID,
	})
	if err != nil {
		return nil, err
	}
	if data == nil || len(data.Gitleaks) < 1 {
		return nil, fmt.Errorf("No data for scan gitleaks, project_id=%d, gitleaks_id=%d", projectID, gitleaksID)
	}
	g := data.Gitleaks[0]
	scanStatus := code.PutGitleaksRequest{
		ProjectId: g.ProjectId,
		Gitleaks: &code.GitleaksForUpsert{
			GitleaksId:          g.GitleaksId,
			CodeDataSourceId:    g.CodeDataSourceId,
			Name:                g.Name,
			Type:                g.Type,
			TargetResource:      g.TargetResource,
			RepositoryPattern:   g.RepositoryPattern,
			GithubUser:          g.GithubUser,
			PersonalAccessToken: g.PersonalAccessToken,
			GitleaksConfig:      g.GitleaksConfig,
			ProjectId:           g.ProjectId,
			ScanAt:              time.Now().Unix(),
			Status:              code.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:        "",
		},
	}
	return &scanStatus, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {
		// finding
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		// finding-tag
		s.tagFinding(ctx, common.TagCode, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, common.TagGitleaks, resp.Finding.FindingId, resp.Finding.ProjectId)
		appLogger.Infof("Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	}
	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, tag string, findingID uint64, projectID uint32) error {
	_, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}})
	if err != nil {
		appLogger.Errorf("Failed to TagFinding, finding_id=%d, tag=%s, error=%+v", findingID, tag, err)
		return err
	}
	return nil
}

func (s *sqsHandler) updateScanStatusError(ctx context.Context, putData *code.PutGitleaksRequest, statusDetail string) error {
	putData.Gitleaks.Status = code.Status_ERROR
	if len(statusDetail) > 200 {
		statusDetail = statusDetail[:200] + " ..." // cut long text
	}
	putData.Gitleaks.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, putData *code.PutGitleaksRequest) error {
	putData.Gitleaks.Status = code.Status_OK
	putData.Gitleaks.StatusDetail = ""
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatus(ctx context.Context, putData *code.PutGitleaksRequest) error {
	resp, err := s.codeClient.PutGitleaks(ctx, putData)
	if err != nil {
		return err
	}
	appLogger.Infof("Success to update AWS status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

// func scoreGitleaks(user *iamUser) float32 {
// 	isAdmin := false
// 	if user.IsUserAdmin || user.IsGroupAdmin {
// 		isAdmin = true
// 	}
// 	if !isAdmin {
// 		return 0.3
// 	}
// 	if isAdmin && user.EnabledPermissionBoundory {
// 		return 0.7
// 	}
// 	return 0.9
// }
