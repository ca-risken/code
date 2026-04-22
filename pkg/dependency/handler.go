package dependency

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
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/ca-risken/datasource-api/proto/code"
	vulnsdk "github.com/ca-risken/vulnerability/pkg/sdk"
	"github.com/google/go-github/v44/github"
)

type sqsHandler struct {
	cipherBlock           cipher.Block
	dependencyClient      dependencyServiceClient
	findingClient         finding.FindingServiceClient
	alertClient           alert.AlertServiceClient
	codeClient            code.CodeServiceClient
	vulnClient            *vulnsdk.Client
	limitRepositorySizeKb int
	logger                logging.Logger
}

func NewHandler(
	ctx context.Context,
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	cc code.CodeServiceClient,
	vulnClient *vulnsdk.Client,
	codeDataKey string,
	trivyPath string,
	limitRepositorySizeKb int,
	l logging.Logger,
) (*sqsHandler, error) {
	key := []byte(codeDataKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher, err=%w", err)
	}
	dependencyConf := &dependencyConfig{
		trivyPath: trivyPath,
	}
	return &sqsHandler{
		cipherBlock:           block,
		dependencyClient:      newDependencyClient(dependencyConf, l),
		findingClient:         fc,
		alertClient:           ac,
		codeClient:            cc,
		vulnClient:            vulnClient,
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

	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}
	s.logger.Infof(ctx, "start Scan, RequestID=%s", requestID)
	gitHubSetting, err := s.getGitHubSetting(ctx, msg.ProjectID, msg.GitHubSettingID)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get scan setting: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	return s.handleRepositoryScan(ctx, msg, gitHubSetting, requestID)
}

func (s *sqsHandler) skipScan(ctx context.Context, repo *github.Repository, limitRepositorySize int) bool {
	repoName := repo.GetFullName()

	if repo.GetFork() {
		s.logger.Infof(ctx, "Skip scan for %s repository(fork repo)", repoName)
		return true
	}
	// repositoryがemptyの場合にスキャンに失敗するためスキップする
	repoSize := repo.GetSize()
	if repoSize == 0 {
		s.logger.Infof(ctx, "Skip scan for %s repository(empty)", repoName)
		return true
	}
	// Hard limit size
	if repoSize > limitRepositorySize {
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
	if data == nil || data.GithubSetting == nil || data.GithubSetting.DependencySetting == nil {
		return nil, fmt.Errorf("no data for dependency scan, project_id=%d, github_setting_id=%d", projectID, GitHubSettingID)
	}
	if data.GithubSetting.PersonalAccessToken == "" {
		return data.GithubSetting, nil
	}
	token, err := codecrypto.DecryptWithBase64(&s.cipherBlock, data.GithubSetting.PersonalAccessToken)
	if err != nil {
		return nil, err
	}
	data.GithubSetting.PersonalAccessToken = token // Set the plaintext so that the value is still decipherable next processes.
	return data.GithubSetting, nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

func (s *sqsHandler) handleRepositoryScan(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, requestID string) error {
	repos := common.GetRepositoriesFromCodeQueueMessage(msg)
	if len(repos) == 0 {
		err := fmt.Errorf("repository metadata is required in queue message")
		if updateErr := s.updateDependencySettingStatusError(ctx, gitHubSetting, err.Error()); updateErr != nil {
			s.logger.Warnf(ctx, "Failed to update dependency setting status error: github_setting_id=%d, err=%+v", msg.GitHubSettingID, updateErr)
		}
		s.logger.Warnf(ctx, "Missing repository metadata in queue message: project_id=%d, github_setting_id=%d", msg.ProjectID, msg.GitHubSettingID)
		return mimosasqs.WrapNonRetryable(err)
	}

	s.logger.Infof(ctx, "Got repositories from queue message: request_id=%s, count=%d, baseURL=%s, target=%s",
		requestID, len(repos), gitHubSetting.BaseUrl, gitHubSetting.TargetResource)
	repos = common.FilterByNamePattern(repos, gitHubSetting.DependencySetting.RepositoryPattern)

	return s.orchestrateScanningProcess(ctx, msg, gitHubSetting, repos, requestID)
}

func (s *sqsHandler) orchestrateScanningProcess(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, repos []*github.Repository, requestID string) error {
	beforeScanAt := time.Now()

	// Step 1: Scan repositories (includes per-repo find/put/clear)
	successfullyScannedRepos, err := s.scanAllRepositories(ctx, msg, gitHubSetting, beforeScanAt, repos)
	if err != nil {
		return err
	}

	// Step 2: Post-scan processing (end log / alert analysis)
	return s.postScanProcessing(ctx, msg, successfullyScannedRepos, requestID)
}

// scanAllRepositories scans all repositories and returns successfully scanned repository names
func (s *sqsHandler) scanAllRepositories(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, beforeScanAt time.Time, repos []*github.Repository) ([]string, error) {
	successfullyScannedRepos := []string{}
	for _, r := range repos {
		if err := common.ValidateRepository(r, gitHubSetting.BaseUrl); err != nil {
			if r == nil || r.GetFullName() == "" {
				if updateErr := s.updateDependencySettingStatusError(ctx, gitHubSetting, err.Error()); updateErr != nil {
					s.logger.Warnf(ctx, "Failed to update dependency setting status error: github_setting_id=%d, err=%+v", msg.GitHubSettingID, updateErr)
				}
				return successfullyScannedRepos, mimosasqs.WrapNonRetryable(err)
			}
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, r.GetFullName(), err.Error())
			return successfullyScannedRepos, mimosasqs.WrapNonRetryable(err)
		}
		if s.skipScan(ctx, r, s.limitRepositorySizeKb) {
			continue
		}
		repoFullName := r.GetFullName()

		if err := s.updateRepositoryStatusInProgress(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName); err != nil {
			s.logger.Warnf(ctx, "Failed to update repository status to IN_PROGRESS: repository_name=%s, err=%+v", repoFullName, err)
		}

		if err := s.scanRepository(ctx, msg, gitHubSetting, beforeScanAt, r); err != nil {
			return successfullyScannedRepos, err
		}
		successfullyScannedRepos = append(successfullyScannedRepos, repoFullName)
	}
	return successfullyScannedRepos, nil
}

func (s *sqsHandler) scanRepository(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, beforeScanAt time.Time, r *github.Repository) error {
	repoFullName := r.GetFullName()

	resultFilePath := fmt.Sprintf("/tmp/%v_%v_%s_%v.json", msg.ProjectID, msg.GitHubSettingID, *r.Name, time.Now().Unix())
	result, err := s.dependencyClient.getResult(ctx, *r.CloneURL, gitHubSetting.PersonalAccessToken, resultFilePath)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to scan repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
		return mimosasqs.WrapNonRetryable(err)
	}

	findings, err := s.makeFindings(ctx, msg, result, r.GetID())
	if err != nil {
		s.logger.Errorf(ctx, "Failed to make findings: github_setting_id=%d, repository_name=%s, err=%+v", msg.GitHubSettingID, r.GetFullName(), err)
		s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
		return mimosasqs.WrapNonRetryable(err)
	}

	if err := s.putFindings(ctx, msg.ProjectID, findings); err != nil {
		s.logger.Errorf(ctx, "failed to put findings: github_setting_id=%d, repository_name=%s, err=%+v", msg.GitHubSettingID, r.GetFullName(), err)
		s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
		return mimosasqs.WrapNonRetryable(err)
	}

	if err := s.putResource(ctx, msg.ProjectID, *r.FullName); err != nil {
		s.logger.Errorf(ctx, "Failed to put resource: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
		return mimosasqs.WrapNonRetryable(err)
	}

	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: message.DependencyDataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{fmt.Sprintf("repository_id:%v", r.GetID())},
		BeforeAt:   beforeScanAt.Unix(),
	}); err != nil {
		s.logger.Errorf(ctx, "Failed to clear finding score. repository: %v, error: %v", r.Name, err)
		s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
		return mimosasqs.WrapNonRetryable(err)
	}

	if err := s.updateRepositoryStatusSuccess(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName); err != nil {
		s.logger.Warnf(ctx, "Failed to update repository status success: repository_name=%s, err=%+v", repoFullName, err)
	}
	return nil
}

// postScanProcessing handles tasks after repository scans
func (s *sqsHandler) postScanProcessing(ctx context.Context, msg *message.CodeQueueMessage, successfullyScannedRepos []string, requestID string) error {
	s.logger.Infof(ctx, "end Scan, RequestID=%s", requestID)
	s.logger.Infof(ctx, "scanned repositories count=%d", len(successfullyScannedRepos))

	if msg.ScanOnly {
		return nil
	}

	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		s.logger.Notifyf(ctx, logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	return nil
}

func sanitizeStatusDetail(status code.Status, statusDetail string) string {
	if status != code.Status_ERROR {
		return statusDetail
	}
	// Sanitize invalid UTF-8 characters to prevent gRPC marshaling errors
	statusDetail = strings.ToValidUTF8(statusDetail, "")
	statusDetail = common.CutString(statusDetail, 200)
	// Re-sanitize after CutString to prevent invalid UTF-8 from byte-level truncation
	return strings.ToValidUTF8(statusDetail, "")
}

func (s *sqsHandler) updateRepositoryStatusInProgress(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName string) error {
	return s.updateRepositoryStatus(ctx, projectID, githubSettingID, repositoryFullName, code.Status_IN_PROGRESS, "")
}

func (s *sqsHandler) updateRepositoryStatusError(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName, statusDetail string) error {
	return s.updateRepositoryStatus(ctx, projectID, githubSettingID, repositoryFullName, code.Status_ERROR, statusDetail)
}

func (s *sqsHandler) updateRepositoryStatusSuccess(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName string) error {
	return s.updateRepositoryStatus(ctx, projectID, githubSettingID, repositoryFullName, code.Status_OK, "")
}

func (s *sqsHandler) updateRepositoryStatus(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName string, status code.Status, statusDetail string) error {
	resp, err := s.codeClient.PutDependencyRepository(ctx, &code.PutDependencyRepositoryRequest{
		ProjectId: projectID,
		DependencyRepository: &code.DependencyRepositoryForUpsert{
			GithubSettingId:    githubSettingID,
			RepositoryFullName: repositoryFullName,
			Status:             status,
			StatusDetail:       sanitizeStatusDetail(status, statusDetail),
			ScanAt:             time.Now().Unix(),
		},
	})
	if err != nil {
		return err
	}
	s.logger.Infof(ctx, "Success to update repository scan status, repository=%s, status=%v, response=%+v", repositoryFullName, status, resp)
	return nil
}

// updateRepositoryStatusErrorWithWarn updates repository status to ERROR and logs a warning if the update fails
func (s *sqsHandler) updateRepositoryStatusErrorWithWarn(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName, statusDetail string) {
	if err := s.updateRepositoryStatusError(ctx, projectID, githubSettingID, repositoryFullName, statusDetail); err != nil {
		s.logger.Warnf(ctx, "Failed to update repository status error: repository_name=%s, err=%+v", repositoryFullName, err)
	}
}

func (s *sqsHandler) updateDependencySettingStatusError(ctx context.Context, gitHubSetting *code.GitHubSetting, statusDetail string) error {
	if gitHubSetting == nil || gitHubSetting.DependencySetting == nil {
		return fmt.Errorf("dependency setting is required")
	}
	resp, err := s.codeClient.PutDependencySetting(ctx, &code.PutDependencySettingRequest{
		ProjectId: gitHubSetting.DependencySetting.ProjectId,
		DependencySetting: &code.DependencySettingForUpsert{
			GithubSettingId:   gitHubSetting.DependencySetting.GithubSettingId,
			CodeDataSourceId:  gitHubSetting.DependencySetting.CodeDataSourceId,
			ProjectId:         gitHubSetting.DependencySetting.ProjectId,
			RepositoryPattern: gitHubSetting.DependencySetting.RepositoryPattern,
			Status:            code.Status_ERROR,
			StatusDetail:      sanitizeStatusDetail(code.Status_ERROR, statusDetail),
			ScanAt:            time.Now().Unix(),
		},
	})
	if err != nil {
		return err
	}
	s.logger.Infof(ctx, "Success to update dependency setting status, github_setting_id=%d, status=%v, response=%+v",
		gitHubSetting.DependencySetting.GithubSettingId, code.Status_ERROR, resp)
	return nil
}
