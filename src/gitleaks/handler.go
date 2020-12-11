package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"strings"
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
	gitleaksConfig, err := s.getGitleaks(ctx, message.ProjectID, message.GitleaksID)
	if err != nil {
		appLogger.Errorf("Failed to get scan status: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
		return err
	}
	decryptedKey, err := common.DecryptWithBase64(&s.cipherBlock, gitleaksConfig.PersonalAccessToken)
	if err != nil {
		appLogger.Errorf("Failed to decrypted personal access token: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
	}
	gitleaksConfig.PersonalAccessToken = decryptedKey // Set the plaintext so that the value is still decipherable after updated.
	scanStatus := s.initScanStatus(gitleaksConfig, gitleaksConfig.PersonalAccessToken)

	// Get repositories
	findings := []repositoryFinding{}
	if err := s.listRepository(ctx, gitleaksConfig, &findings); err != nil {
		appLogger.Errorf("Failed to list repositories: gitleaks_id=%d, err=%+v", message.GitleaksID, err)
		return s.updateScanStatusError(ctx, scanStatus, err.Error())
	}
	appLogger.Debugf("Got repositories, count=%d, target=%s", len(findings), gitleaksConfig.TargetResource)

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
	}
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return err
	}
	return s.analyzeAlert(ctx, message.ProjectID)
}

func (s *sqsHandler) getGitleaks(ctx context.Context, projectID, gitleaksID uint32) (*code.Gitleaks, error) {
	data, err := s.codeClient.GetGitleaks(ctx, &code.GetGitleaksRequest{
		ProjectId:  projectID,
		GitleaksId: gitleaksID,
	})
	if err != nil {
		return nil, err
	}
	if data == nil || data.Gitleaks == nil {
		return nil, fmt.Errorf("No data for scan gitleaks, project_id=%d, gitleaks_id=%d", projectID, gitleaksID)
	}
	return data.Gitleaks, nil
}

func (s *sqsHandler) initScanStatus(g *code.Gitleaks, token string) *code.PutGitleaksRequest {
	return &code.PutGitleaksRequest{
		ProjectId: g.ProjectId,
		Gitleaks: &code.GitleaksForUpsert{
			GitleaksId:          g.GitleaksId,
			CodeDataSourceId:    g.CodeDataSourceId,
			Name:                g.Name,
			Type:                g.Type,
			TargetResource:      g.TargetResource,
			RepositoryPattern:   g.RepositoryPattern,
			GithubUser:          g.GithubUser,
			PersonalAccessToken: token,
			ScanPublic:          g.ScanPublic,
			ScanInternal:        g.ScanInternal,
			ScanPrivate:         g.ScanPrivate,
			GitleaksConfig:      g.GitleaksConfig,
			ProjectId:           g.ProjectId,
			ScanAt:              time.Now().Unix(),
			Status:              code.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:        "",
		},
	}
}

func (s *sqsHandler) listRepository(ctx context.Context, config *code.Gitleaks, findings *[]repositoryFinding) error {
	switch config.Type {
	case code.Type_ENTERPRISE:
		if err := s.listRepositoryEnterprise(ctx, config, findings); err != nil {
			return err
		}
	case code.Type_ORGANIZATION, code.Type_USER:
		if err := s.githubClient.listRepository(ctx, config, findings); err != nil {
			return err
		}
	default:
		return fmt.Errorf("Unknown github type: type=%+v", config.Type)
	}
	return nil
}

func (s *sqsHandler) listRepositoryEnterprise(ctx context.Context, config *code.Gitleaks, findings *[]repositoryFinding) error {
	list, err := s.listEnterpriseOrg(ctx, config, findings)
	if err != nil {
		return err
	}
	if list == nil {
		return nil
	}
	for _, org := range list.EnterpriseOrg {
		config.Type = code.Type_ORGANIZATION
		config.TargetResource = org.Login
		if err := s.githubClient.listRepository(ctx, config, findings); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqsHandler) listEnterpriseOrg(ctx context.Context, config *code.Gitleaks, findings *[]repositoryFinding) (*code.ListEnterpriseOrgResponse, error) {
	orgs, err := s.githubClient.listEnterpriseOrg(ctx, config, config.TargetResource)
	if err != nil {
		return &code.ListEnterpriseOrgResponse{}, err
	}
	existsOrgMap := make(map[string]bool)
	// update enterprise orgs
	for _, org := range *orgs {
		existsOrgMap[org.Login] = true
		if _, err := s.codeClient.PutEnterpriseOrg(ctx, &code.PutEnterpriseOrgRequest{
			ProjectId: config.ProjectId,
			EnterpriseOrg: &code.EnterpriseOrgForUpsert{
				GitleaksId: config.GitleaksId,
				Login:      org.Login,
				ProjectId:  config.ProjectId,
			},
		}); err != nil {
			appLogger.Errorf("Failed to PutEnterpriseOrg API, err=%+v", err)
			return &code.ListEnterpriseOrgResponse{}, err
		}
	}

	// delete enterprise orgs
	if len(*orgs) > 0 {
		list, err := s.codeClient.ListEnterpriseOrg(ctx, &code.ListEnterpriseOrgRequest{
			ProjectId:  config.ProjectId,
			GitleaksId: config.GitleaksId,
		})
		if err != nil {
			appLogger.Errorf("Failed to ListEnterpriseOrg API, err=%+v", err)
			return &code.ListEnterpriseOrgResponse{}, err
		}
		for _, org := range list.EnterpriseOrg {
			if _, ok := existsOrgMap[org.Login]; ok {
				continue
			}
			if _, err := s.codeClient.DeleteEnterpriseOrg(ctx, &code.DeleteEnterpriseOrgRequest{
				ProjectId:  config.ProjectId,
				GitleaksId: config.GitleaksId,
				Login:      org.Login,
			}); err != nil {
				appLogger.Errorf("Failed to DeleteEnterpriseOrg API, err=%+v", err)
				return &code.ListEnterpriseOrgResponse{}, err
			}
		}
	}
	updatedList, err := s.codeClient.ListEnterpriseOrg(ctx, &code.ListEnterpriseOrgRequest{
		ProjectId:  config.ProjectId,
		GitleaksId: config.GitleaksId,
	})
	if err != nil {
		appLogger.Errorf("Failed to ListEnterpriseOrg API, err=%+v", err)
		return &code.ListEnterpriseOrgResponse{}, err
	}
	return updatedList, nil
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
		repository := f
		leak.generateDataSourceID()
		repository.LastScanedAt = time.Now()
		repository.LeakFindings = []*leakFinding{leak} // set only one lesk for putting the finding json data.
		buf, err := json.Marshal(repository)
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
		if leak.Tags != "" {
			for _, tag := range strings.Split(leak.Tags, ",") {
				s.tagFinding(ctx, strings.TrimSpace(tag), resp.Finding.FindingId, resp.Finding.ProjectId)
			}
		}
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
	for _, leak := range f.LeakFindings {
		if leak.Rule == "" {
			continue
		}
		if existsCriticalRule(strings.TrimSpace(leak.Rule)) {
			return 0.8
		}
	}
	return 0.6
}

// check default ruleset(description) https://github.com/zricethezav/gitleaks/blob/master/config/default.go
var criticalRule = []string{
	"AWS Access Key",
	"AWS Secret Key",
	"AWS MWS key",
	"Facebook Secret Key",
	"Twitter Secret Key",
	"LinkedIn Secret Key",
	"Google (GCP) Service Account",
	"Heroku API key",
	"MailChimp API key",
	"Mailgun API key",
	"PayPal Braintree access token",
	"Picatic API key",
	"SendGrid API Key",
	"Stripe API key",
	"Square access token",
	"Square OAuth secret",
	"Twilio API key",
	"Dynatrace ttoken",
	"Shopify shared secret",
	"Shopify access token",
	"Shopify custom app access token",
	"Shopify private app access token",
}

func existsCriticalRule(rule string) bool {
	for _, r := range criticalRule {
		if r == rule {
			return true
		}
	}
	return false
}
