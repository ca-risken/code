package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
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
	findings := []repositoryFinding{}
	if err := s.githubClient.listRepository(ctx,
		scanStatus.Gitleaks.Type,
		scanStatus.Gitleaks.TargetResource,
		scanStatus.Gitleaks.RepositoryPattern,
		decryptedKey,
		&findings,
	); err != nil {
		appLogger.Errorf("Failed to list repositories: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
		return s.updateScanStatusError(ctx, scanStatus, err.Error())
	}
	appLogger.Debugf("Got repositories, count=%d", len(findings))

	for _, f := range findings {
		// Set LastScanedAt
		if err := s.setLastScanedAt(ctx, message.ProjectID, &f); err != nil {
			appLogger.Errorf("Failed to set LastScanedAt: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}

		// Scan repository
		if err := s.gitleaksClient.scanRepository(ctx, decryptedKey, &f); err != nil {
			appLogger.Errorf("Failed to scan repositories: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}

		// Put finding
		if err := s.putFindings(ctx, message.ProjectID, &f); err != nil {
			appLogger.Errorf("Failed to put findngs: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
		if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
			return err
		}
	}
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

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, f *repositoryFinding) error {
	if len(f.LeakFindings) < 1 {
		// put Resource only (for cacheing scaned time.)
		resp, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
			ProjectId: projectID,
			Resource: &finding.ResourceForUpsert{
				ResourceName: *f.FullName,
				ProjectId:    projectID,
			},
		})
		if err != nil {
			appLogger.Errorf("Failed to put resource project_id=%d, repository=%s, err=%+v", projectID, *f.FullName, err)
			return err
		}
		appLogger.Infof("Success to PutResource, resource_id=%d", resp.Resource.ResourceId)
		return nil
	}

	// Exists leaks
	for _, leak := range f.LeakFindings {
		// finding
		leak.generateDataSourceID()
		buf, err := json.Marshal(leak)
		if err != nil {
			appLogger.Errorf("Failed to marshal user data, project_id=%d, repository=%s, err=%+v", projectID, *f.FullName, err)
			return err
		}
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
			Finding: &finding.FindingForUpsert{
				Description:      fmt.Sprintf("Code secrets scanning by the gitleas for %s", *f.FullName),
				DataSource:       common.GitleaksDataSource,
				DataSourceId:     leak.DataSourceID,
				ResourceName:     *f.FullName,
				ProjectId:        projectID,
				OriginalScore:    scoreGitleaks(f),
				OriginalMaxScore: 1.0,
				Data:             string(buf),
			},
		})
		if err != nil {
			appLogger.Errorf("Failed to put finding project_id=%d, repository=%s, err=%+v", projectID, *f.FullName, err)
			return err
		}
		// finding-tag
		s.tagFinding(ctx, common.TagCode, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, common.TagGitleaks, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, *f.Visibility, resp.Finding.FindingId, resp.Finding.ProjectId)
		appLogger.Infof("Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	}
	return nil
}

func (s *sqsHandler) setLastScanedAt(ctx context.Context, projectID uint32, f *repositoryFinding) error {
	resp, err := s.findingClient.ListResource(ctx, &finding.ListResourceRequest{
		ProjectId:    projectID,
		ResourceName: []string{*f.FullName},
	})
	if err != nil {
		appLogger.Errorf("Failed to ListResource, project_id=%d, repository=%s, err=%+v", projectID, *f.FullName, err)
		return err
	}
	if len(resp.ResourceId) < 1 {
		return nil
	}
	resourceID := resp.ResourceId[0]
	resp2, err := s.findingClient.GetResource(ctx, &finding.GetResourceRequest{
		ProjectId:  projectID,
		ResourceId: resourceID,
	})
	if err != nil {
		appLogger.Errorf("Failed to GetResource, project_id=%d, resource_id=%d, err=%+v", projectID, resourceID, err)
		return err
	}
	if resp2 == nil || resp2.Resource == nil {
		return nil
	}
	f.LastScanedAt = time.Unix(resp2.Resource.UpdatedAt, 0)
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
	statusDetail = cutString(statusDetail, 200)
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

func cutString(input string, cut int) string {
	if len(input) > cut {
		return input[:cut] + " ..." // cut long text
	}
	return input
}

func scoreGitleaks(f *repositoryFinding) float32 {
	if len(f.LeakFindings) < 1 {
		return 0.1
	}
	return 0.6
}
