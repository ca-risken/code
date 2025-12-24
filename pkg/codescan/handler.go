package codescan

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"
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
	"github.com/google/go-github/v44/github"
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
	gitHubSetting.PersonalAccessToken = token // Set the plaintext so that the value is still decipherable next processes.

	// Use unified scan logic (handles both organization and repository scans)
	return s.handleRepositoryScan(ctx, msg, gitHubSetting, token)
}

// handleRepositoryScan handles scanning for repositories (all or single based on RepositoryName)
func (s *sqsHandler) handleRepositoryScan(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string) error {
	// Get repositories (will return all repos or single repo based on RepositoryName)
	repos, err := s.githubClient.ListRepository(ctx, gitHubSetting, msg.RepositoryName)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to list repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		// Update repository status to ERROR if repository_name is specified
		if msg.RepositoryName != "" {
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, msg.RepositoryName, err.Error())
		}
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "Got repositories, count=%d, baseURL=%s, target=%s, repository_name=%s",
		len(repos), gitHubSetting.BaseUrl, gitHubSetting.TargetResource, msg.RepositoryName)

	// Filtered By Visibility
	repos = common.FilterByVisibility(repos, gitHubSetting.CodeScanSetting.ScanPublic, gitHubSetting.CodeScanSetting.ScanInternal, gitHubSetting.CodeScanSetting.ScanPrivate)
	// Filtered By Name
	repos = common.FilterByNamePattern(repos, gitHubSetting.CodeScanSetting.RepositoryPattern)

	// Scan repositories using common logic
	return s.scanRepositories(ctx, msg, gitHubSetting, token, repos)
}

// scanRepositories orchestrates the scanning process for repositories
func (s *sqsHandler) scanRepositories(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string, repos []*github.Repository) error {
	beforeScanAt := time.Now()

	// Step 1: Scan all repositories
	semgrepFindings, successfullyScannedRepos, err := s.scanAllRepositories(ctx, msg, gitHubSetting, token, repos)
	if err != nil {
		return err
	}

	// Step 2: Save findings
	if err := s.saveFindings(ctx, msg, semgrepFindings, successfullyScannedRepos); err != nil {
		return err
	}

	// Step 3: Post-scan processing (clear scores and analyze alerts)
	if err := s.postScanProcessing(ctx, msg, successfullyScannedRepos, beforeScanAt); err != nil {
		return err
	}

	return nil
}

// scanAllRepositories scans all repositories and returns findings and successfully scanned repository names
func (s *sqsHandler) scanAllRepositories(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string, repos []*github.Repository) ([]*SemgrepFinding, []string, error) {
	semgrepFindings := []*SemgrepFinding{}
	successfullyScannedRepos := []string{}

	for _, r := range repos {
		if s.skipScan(ctx, r, s.limitRepositorySizeKb) {
			continue
		}

		repoFullName := r.GetFullName()

		// Update repository status to IN_PROGRESS
		if err := s.updateRepositoryStatusInProgress(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName); err != nil {
			s.logger.Warnf(ctx, "Failed to update repository status to IN_PROGRESS: repository_name=%s, err=%+v", repoFullName, err)
		}

		// Scan source code
		scanResult, err := s.scanForRepository(ctx, r, token, gitHubSetting.BaseUrl)
		if err != nil {
			// Scan failed - update status to ERROR
			s.logger.Errorf(ctx, "failed to codeScan scan: repository_name=%s, err=%+v", repoFullName, err)
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
			// Continue to next repository instead of returning error
			continue
		}

		// Append findings to the outer scope variable
		semgrepFindings = append(semgrepFindings, scanResult...)
		successfullyScannedRepos = append(successfullyScannedRepos, repoFullName)

		// Update repository status to OK
		if err := s.updateRepositoryStatusSuccess(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName); err != nil {
			s.logger.Warnf(ctx, "Failed to update repository status success: repository_name=%s, err=%+v", repoFullName, err)
		}
	}

	return semgrepFindings, successfullyScannedRepos, nil
}

// saveFindings saves findings and handles failures by updating repository statuses
func (s *sqsHandler) saveFindings(ctx context.Context, msg *message.CodeQueueMessage, semgrepFindings []*SemgrepFinding, successfullyScannedRepos []string) error {
	if err := s.putSemgrepFindings(ctx, msg.ProjectID, semgrepFindings); err != nil {
		s.logger.Errorf(ctx, "failed to put findings: err=%+v", err)
		// Update all repositories that were already set to Status_OK back to Status_ERROR when findings save fails
		for _, repoFullName := range successfullyScannedRepos {
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, fmt.Sprintf("failed to put findings: %v", err))
		}
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

// postScanProcessing performs post-scan tasks: clearing scores and analyzing alerts
func (s *sqsHandler) postScanProcessing(ctx context.Context, msg *message.CodeQueueMessage, successfullyScannedRepos []string, beforeScanAt time.Time) error {
	// Clear score for inactive findings
	if err := s.clearScoresForRepositories(ctx, msg, successfullyScannedRepos, beforeScanAt); err != nil {
		return err
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

func (s *sqsHandler) skipScan(ctx context.Context, repo *github.Repository, limitRepositorySize int) bool {
	if repo == nil {
		s.logger.Warnf(ctx, "Skip scan repository(data not found)")
		return true
	}

	repoName := ""
	if repo.FullName != nil {
		repoName = *repo.FullName
	}
	if repo.Archived != nil && *repo.Archived {
		s.logger.Infof(ctx, "Skip scan for %s repository(archived)", repoName)
		return true
	}
	if repo.Fork != nil && *repo.Fork {
		s.logger.Infof(ctx, "Skip scan for %s repository(fork repo)", repoName)
		return true
	}
	if repo.Disabled != nil && *repo.Disabled {
		s.logger.Infof(ctx, "Skip scan for %s repository(disabled)", repoName)
		return true
	}
	if repo.Size != nil && *repo.Size < 1 {
		s.logger.Infof(ctx, "Skip scan for %s repository(empty)", repoName)
		return true
	}

	// Hard limit size
	if repo.Size != nil && *repo.Size > limitRepositorySize {
		s.logger.Warnf(ctx, "Skip scan for %s repository(too big size, limit=%dkb, size(kb)=%dkb)", repoName, limitRepositorySize, *repo.Size)
		return true
	}
	return false
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

func (s *sqsHandler) updateRepositoryStatusInProgress(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName string) error {
	return s.updateRepositoryStatus(ctx, projectID, githubSettingID, repositoryFullName, code.Status_IN_PROGRESS, "")
}

func (s *sqsHandler) updateRepositoryStatusError(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName, statusDetail string) error {
	// Sanitize invalid UTF-8 characters to prevent gRPC marshaling errors
	statusDetail = strings.ToValidUTF8(statusDetail, "")
	statusDetail = common.CutString(statusDetail, 200)
	return s.updateRepositoryStatus(ctx, projectID, githubSettingID, repositoryFullName, code.Status_ERROR, statusDetail)
}

func (s *sqsHandler) updateRepositoryStatusSuccess(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName string) error {
	return s.updateRepositoryStatus(ctx, projectID, githubSettingID, repositoryFullName, code.Status_OK, "")
}

func (s *sqsHandler) updateRepositoryStatus(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName string, status code.Status, statusDetail string) error {
	resp, err := s.codeClient.PutCodeScanRepository(ctx, &code.PutCodeScanRepositoryRequest{
		ProjectId: projectID,
		CodeScanRepository: &code.CodeScanRepositoryForUpsert{
			GithubSettingId:    githubSettingID,
			RepositoryFullName: repositoryFullName,
			Status:             status,
			StatusDetail:       statusDetail,
			ScanAt:             time.Now().Unix(),
		},
	})
	if err != nil {
		return err
	}
	s.logger.Infof(ctx, "Success to update repository scan status, repository=%s, status=%s, response=%+v", repositoryFullName, status, resp)
	return nil
}

// updateRepositoryStatusErrorWithWarn updates repository status to ERROR and logs a warning if the update fails
func (s *sqsHandler) updateRepositoryStatusErrorWithWarn(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName, statusDetail string) {
	if err := s.updateRepositoryStatusError(ctx, projectID, githubSettingID, repositoryFullName, statusDetail); err != nil {
		s.logger.Warnf(ctx, "Failed to update repository status error: repository_name=%s, err=%+v", repositoryFullName, err)
	}
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

// clearScoresForRepositories clears finding scores for successfully scanned repositories
func (s *sqsHandler) clearScoresForRepositories(ctx context.Context, msg *message.CodeQueueMessage, successfullyScannedRepos []string, beforeScanAt time.Time) error {
	for _, repoFullName := range successfullyScannedRepos {
		if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
			DataSource: message.CodeScanDataSource,
			ProjectId:  msg.ProjectID,
			Tag:        []string{tagCodeScan, repoFullName},
			BeforeAt:   beforeScanAt.Unix(),
		}); err != nil {
			s.logger.Errorf(ctx, "Failed to clear finding score. project_id: %v, repo: %s, error: %v", msg.ProjectID, repoFullName, err)
			// Update repository status to ERROR when ClearScore fails
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, fmt.Sprintf("failed to clear finding score: %v", err))
			return mimosasqs.WrapNonRetryable(err)
		}

	}
	return nil
}
