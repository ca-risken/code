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
	cipherBlock           cipher.Block
	githubClient          githubcli.GithubServiceClient
	findingClient         finding.FindingServiceClient
	alertClient           alert.AlertServiceClient
	codeClient            code.CodeServiceClient
	limitRepositorySizeKb int
	logger                logging.Logger
}

func NewHandler(
	ctx context.Context,
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	cc code.CodeServiceClient,
	codeDataKey string,
	githubDefaultToken string,
	limitRepositorySizeKb int,
	l logging.Logger,
) (*sqsHandler, error) {
	key := []byte(codeDataKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &sqsHandler{
		cipherBlock:           block,
		githubClient:          githubcli.NewGithubClient(githubDefaultToken, l),
		findingClient:         fc,
		alertClient:           ac,
		codeClient:            cc,
		limitRepositorySizeKb: limitRepositorySizeKb,
		logger:                l,
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
	gitHubSetting.PersonalAccessToken = token
	return s.handleRepoScan(ctx, msg, gitHubSetting, token)
}

func (s *sqsHandler) handleRepoScan(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string) error {
	scanStatus := s.initScanStatus(gitHubSetting.CodeScanSetting)

	if err := s.updateUsrOrgStatusToInProgress(ctx, scanStatus); err != nil {
		s.logger.Warnf(ctx, "Failed to update usrOrg status to IN_PROGRESS: err=%+v", err)
	}

	if msg.RepositoryName != "" {
		return s.handleSingleRepoScan(ctx, msg, gitHubSetting, token, scanStatus)
	}
	return s.handleUserOrgScan(ctx, msg, gitHubSetting, token, scanStatus)
}

func (s *sqsHandler) handleSingleRepoScan(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string, scanStatus *code.PutCodeScanSettingRequest) error {
	repoListResp, err := s.codeClient.ListCodescanTargetRepository(ctx, &code.ListCodescanTargetRepositoryRequest{
		ProjectId:       msg.ProjectID,
		GithubSettingId: msg.GitHubSettingID,
	})
	if err != nil {
		s.logger.Errorf(ctx, "Failed to list repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		s.wrapUpdateUserOrgStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	var targetRepo *code.GitHubRepository
	for _, repo := range repoListResp.Repository {
		if repo.FullName == msg.RepositoryName {
			targetRepo = repo
			break
		}
	}
	if targetRepo == nil {
		err := fmt.Errorf("repository not found: repository_name=%s", msg.RepositoryName)
		s.wrapUpdateUserOrgStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	s.logger.Infof(ctx, "Processing repository: repository_name=%s, baseURL=%s, target=%s",
		msg.RepositoryName, gitHubSetting.BaseUrl, gitHubSetting.TargetResource)

	err = s.scanSingleRepository(ctx, msg, gitHubSetting, token, targetRepo, scanStatus)
	if err != nil {
		return err
	}

	if err := s.updateUsrOrgStatusToOK(ctx, scanStatus); err != nil {
		s.logger.Warnf(ctx, "Failed to update usrOrg status to OK: err=%+v", err)
	}

	return nil
}

func (s *sqsHandler) handleUserOrgScan(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string, scanStatus *code.PutCodeScanSettingRequest) error {
	repoListResp, err := s.codeClient.ListCodescanTargetRepository(ctx, &code.ListCodescanTargetRepositoryRequest{
		ProjectId:       msg.ProjectID,
		GithubSettingId: msg.GitHubSettingID,
	})
	if err != nil {
		s.logger.Errorf(ctx, "Failed to list repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		s.wrapUpdateUserOrgStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	s.logger.Infof(ctx, "Got repositories, count=%d, baseURL=%s, target=%s, repository_pattern=%s",
		len(repoListResp.Repository), gitHubSetting.BaseUrl, gitHubSetting.TargetResource, gitHubSetting.CodeScanSetting.RepositoryPattern)

	for _, repo := range repoListResp.Repository {
		err = s.scanSingleRepository(ctx, msg, gitHubSetting, token, repo, scanStatus)
		if err != nil {
			s.logger.Errorf(ctx, "Failed to scan repository: repository_name=%s, err=%+v", repo.FullName, err)
			continue
		}
	}

	if err := s.updateUsrOrgStatusToOK(ctx, scanStatus); err != nil {
		s.logger.Warnf(ctx, "Failed to update usrOrg status to OK: err=%+v", err)
	}

	return nil
}

func (s *sqsHandler) scanSingleRepository(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string, repo *code.GitHubRepository, scanStatus *code.PutCodeScanSettingRequest) error {
	beforeScanAt := time.Now()
	repoFullName := repo.FullName
	githubSettingID := gitHubSetting.CodeScanSetting.GithubSettingId

	if err := s.updateRepoStatusToInProgress(ctx, msg.ProjectID, githubSettingID, repoFullName); err != nil {
		s.logger.Warnf(ctx, "Failed to update repository status to IN_PROGRESS: repository=%s, err=%+v", repoFullName, err)
	}

	scanResult, err := s.scanForRepository(ctx, repo, token, gitHubSetting.BaseUrl)
	if err != nil {
		s.logger.Errorf(ctx, "failed to codeScan scan: repository_name=%s, err=%+v", repoFullName, err)
		if updateErr := s.updateRepoStatusToError(ctx, msg.ProjectID, githubSettingID, repoFullName, err.Error()); updateErr != nil {
			s.logger.Warnf(ctx, "Failed to update repository status to ERROR: repository=%s, err=%+v", repoFullName, updateErr)
		}
		s.wrapUpdateUserOrgStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	if err := s.putSemgrepFindings(ctx, msg.ProjectID, scanResult); err != nil {
		s.logger.Errorf(ctx, "failed to put findings: err=%+v", err)
		if updateErr := s.updateRepoStatusToError(ctx, msg.ProjectID, githubSettingID, repoFullName, err.Error()); updateErr != nil {
			s.logger.Warnf(ctx, "Failed to update repository status to ERROR: repository=%s, err=%+v", repoFullName, updateErr)
		}
		s.wrapUpdateUserOrgStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: message.CodeScanDataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{tagCodeScan, repoFullName},
		BeforeAt:   beforeScanAt.Unix(),
	}); err != nil {
		s.logger.Errorf(ctx, "Failed to clear finding score. project_id: %v, repo: %s, error: %v", msg.ProjectID, repoFullName, err)
		if updateErr := s.updateRepoStatusToError(ctx, msg.ProjectID, githubSettingID, repoFullName, err.Error()); updateErr != nil {
			s.logger.Warnf(ctx, "Failed to update repository status to ERROR: repository=%s, err=%+v", repoFullName, updateErr)
		}
		s.wrapUpdateUserOrgStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	if err := s.updateRepoStatusToOK(ctx, msg.ProjectID, githubSettingID, repoFullName); err != nil {
		s.logger.Warnf(ctx, "Failed to update repository status to OK: repository=%s, err=%+v", repoFullName, err)
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

func (s *sqsHandler) wrapUpdateUserOrgStatusToError(ctx context.Context, scanStatus *code.PutCodeScanSettingRequest, err error) {
	if updateErr := s.updateUsrOrgStatusToError(ctx, scanStatus, err.Error()); updateErr != nil {
		s.logger.Warnf(ctx, "Failed to update usrOrg status to ERROR: err=%+v", updateErr)
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

func (s *sqsHandler) updateUsrOrgStatusToError(ctx context.Context, putData *code.PutCodeScanSettingRequest, statusDetail string) error {
	putData.CodeScanSetting.Status = code.Status_ERROR
	statusDetail = common.CutString(statusDetail, 200)
	putData.CodeScanSetting.StatusDetail = statusDetail
	return s.updateUsrOrgStatus(ctx, putData)
}

func (s *sqsHandler) updateUsrOrgStatusToInProgress(ctx context.Context, putData *code.PutCodeScanSettingRequest) error {
	putData.CodeScanSetting.Status = code.Status_IN_PROGRESS
	putData.CodeScanSetting.StatusDetail = ""
	return s.updateUsrOrgStatus(ctx, putData)
}

func (s *sqsHandler) updateUsrOrgStatusToOK(ctx context.Context, putData *code.PutCodeScanSettingRequest) error {
	putData.CodeScanSetting.Status = code.Status_OK
	putData.CodeScanSetting.StatusDetail = ""
	return s.updateUsrOrgStatus(ctx, putData)
}

func (s *sqsHandler) updateUsrOrgStatus(ctx context.Context, putData *code.PutCodeScanSettingRequest) error {
	resp, err := s.codeClient.PutCodeScanSetting(ctx, putData)
	if err != nil {
		return err
	}
	s.logger.Infof(ctx, "Success to update usrOrg scan status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

func (s *sqsHandler) updateRepoStatus(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName string, status code.Status, statusDetail string) error {
	_, err := s.codeClient.PutCodeScanRepository(ctx, &code.PutCodeScanRepositoryRequest{
		ProjectId: projectID,
		CodeScanRepository: &code.CodeScanRepositoryForUpsert{
			GithubSettingId:    githubSettingID,
			RepositoryFullName: repositoryFullName,
			Status:             status,
			StatusDetail:       common.CutString(statusDetail, 200),
			ScanAt:             time.Now().Unix(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update repository status: repository=%s, status=%s, err=%w", repositoryFullName, status.String(), err)
	}
	s.logger.Infof(ctx, "Success to update repository status: repository=%s, status=%s", repositoryFullName, status.String())
	return nil
}

func (s *sqsHandler) updateRepoStatusToInProgress(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName string) error {
	return s.updateRepoStatus(ctx, projectID, githubSettingID, repositoryFullName, code.Status_IN_PROGRESS, "")
}

func (s *sqsHandler) updateRepoStatusToOK(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName string) error {
	return s.updateRepoStatus(ctx, projectID, githubSettingID, repositoryFullName, code.Status_OK, "")
}

func (s *sqsHandler) updateRepoStatusToError(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName, statusDetail string) error {
	return s.updateRepoStatus(ctx, projectID, githubSettingID, repositoryFullName, code.Status_ERROR, statusDetail)
}
