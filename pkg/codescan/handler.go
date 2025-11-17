package codescan

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/code/pkg/common"
	codecrypto "github.com/ca-risken/code/pkg/crypto"
	githubcli "github.com/ca-risken/code/pkg/github"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/code"
)

type sqsHandler struct {
	cipherBlock   cipher.Block
	githubClient  githubcli.GithubServiceClient
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	codeClient    code.CodeServiceClient
	logger        logging.Logger
}

func NewHandler(
	ctx context.Context,
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	cc code.CodeServiceClient,
	codeDataKey string,
	githubDefaultToken string,
	l logging.Logger,
) (*sqsHandler, error) {
	key := []byte(codeDataKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &sqsHandler{
		cipherBlock:   block,
		githubClient:  githubcli.NewGithubClient(githubDefaultToken, l),
		findingClient: fc,
		alertClient:   ac,
		codeClient:    cc,
		logger:        l,
	}, nil
}

func (s *sqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Infof(ctx, "got message: %s", msgBody)
	msg, err := message.ParseMessageGitHub(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "Invalid message: msg=%+v, err=%+v", msg, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	gitHubSetting, err := s.getGitHubSetting(ctx, msg.ProjectID, msg.GitHubSettingID)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get scan setting: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	token, err := codecrypto.DecryptWithBase64(&s.cipherBlock, gitHubSetting.PersonalAccessToken)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to decrypt personal access token: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	gitHubSetting.PersonalAccessToken = token // Set the plaintext so that the value is still decipherable next processes.

	// Use unified scan logic (handles both organization and repository scans)
	return s.handleRepositoryScan(ctx, msg, gitHubSetting, token)
}

// handleRepositoryScan handles scanning for repositories (all or single based on RepositoryName)
func (s *sqsHandler) handleRepositoryScan(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string) error {
	scanStatus := s.initScanStatus(gitHubSetting.CodeScanSetting)

	// Get repositories filtered by CodeScanSetting via gRPC API
	resp, err := s.codeClient.ListCodescanTargetRepository(ctx, &code.ListCodescanTargetRepositoryRequest{
		ProjectId:       msg.ProjectID,
		GithubSettingId: msg.GitHubSettingID,
	})
	if err != nil {
		s.logger.Errorf(ctx, "Failed to list repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	repos := resp.Repository
	s.logger.Infof(ctx, "Got repositories, count=%d, baseURL=%s, target=%s, repository_name=%s",
		len(repos), gitHubSetting.BaseUrl, gitHubSetting.TargetResource, msg.RepositoryName)

	// Scan repositories using common logic
	return s.scanRepositories(ctx, msg, gitHubSetting, token, repos, scanStatus)
}

// scanRepositories is the common scanning logic for both organization and repository scans
func (s *sqsHandler) scanRepositories(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string, repos []*code.GitHubRepository, scanStatus *code.PutCodeScanSettingRequest) error {
	beforeScanAt := time.Now()
	semgrepFindings := []*SemgrepFinding{}

	for _, r := range repos {
		// Scan source code
		scanResult, err := s.scanForRepositoryFromProto(ctx, r, token, gitHubSetting.BaseUrl)
		if err != nil {
			s.logger.Errorf(ctx, "failed to codeScan scan: repository_name=%s, err=%+v", r.FullName, err)
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}
		semgrepFindings = append(semgrepFindings, scanResult...)
	}

	if err := s.putSemgrepFindings(ctx, msg.ProjectID, semgrepFindings); err != nil {
		s.logger.Errorf(ctx, "failed to put findings: err=%+v", err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	// Clear score for inactive findings
	for _, r := range repos {
		repo := r.FullName
		if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
			DataSource: message.CodeScanDataSource,
			ProjectId:  msg.ProjectID,
			Tag:        []string{tagCodeScan, repo},
			BeforeAt:   beforeScanAt.Unix(),
		}); err != nil {
			s.logger.Errorf(ctx, "Failed to clear finding score. project_id: %v, repo: %s, error: %v", msg.ProjectID, repo, err)
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}
	}

	// Update status based on scan type
	// Organization scan - update global status
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		s.logger.Notifyf(ctx, logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	return nil
}

func (s *sqsHandler) updateStatusToError(ctx context.Context, scanStatus *code.PutCodeScanSettingRequest, err error) {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		s.logger.Warnf(ctx, "Failed to update scan status error: err=%+v", updateErr)
	}
}

func (s *sqsHandler) getGitHubSetting(ctx context.Context, projectID, GitHubSettingID uint32) (*code.GitHubSetting, error) {
	data, err := s.codeClient.GetGitHubSetting(ctx, &code.GetGitHubSettingRequest{
		ProjectId:       projectID,
		GithubSettingId: GitHubSettingID,
	})
	if err != nil {
		return nil, err
	}
	if data == nil || data.GithubSetting == nil || data.GithubSetting.CodeScanSetting == nil {
		return nil, fmt.Errorf("no data for code scan, project_id=%d, github_setting_id=%d", projectID, GitHubSettingID)
	}
	return data.GithubSetting, nil
}

func (s *sqsHandler) initScanStatus(g *code.CodeScanSetting) *code.PutCodeScanSettingRequest {
	return &code.PutCodeScanSettingRequest{
		ProjectId: g.ProjectId,
		CodeScanSetting: &code.CodeScanSettingForUpsert{
			GithubSettingId:   g.GithubSettingId,
			CodeDataSourceId:  g.CodeDataSourceId,
			RepositoryPattern: g.RepositoryPattern,
			ScanPublic:        g.ScanPublic,
			ScanInternal:      g.ScanInternal,
			ScanPrivate:       g.ScanPrivate,
			ProjectId:         g.ProjectId,
			ScanAt:            time.Now().Unix(),
			Status:            code.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:      "",
		},
	}
}

func (s *sqsHandler) updateScanStatusError(ctx context.Context, putData *code.PutCodeScanSettingRequest, statusDetail string) error {
	putData.CodeScanSetting.Status = code.Status_ERROR
	statusDetail = common.CutString(statusDetail, 200)
	putData.CodeScanSetting.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, putData *code.PutCodeScanSettingRequest) error {
	putData.CodeScanSetting.Status = code.Status_OK
	putData.CodeScanSetting.StatusDetail = ""
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatus(ctx context.Context, putData *code.PutCodeScanSettingRequest) error {
	resp, err := s.codeClient.PutCodeScanSetting(ctx, putData)
	if err != nil {
		return err
	}
	s.logger.Infof(ctx, "Success to update scan status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}
