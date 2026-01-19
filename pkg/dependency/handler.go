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
	githubcli "github.com/ca-risken/code/pkg/github"
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
	githubClient          githubcli.GithubServiceClient
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
	githubDefaultToken string,
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
		githubClient:          githubcli.NewGithubClient(githubDefaultToken, l),
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

	beforeScanAt := time.Now()
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

	// Get repositories (single repo when RepositoryName is specified)
	repos, err := s.githubClient.ListRepository(ctx, gitHubSetting, msg.RepositoryName)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to list repositories: github_setting_id=%d, repository_name=%s, err=%+v", msg.GitHubSettingID, msg.RepositoryName, err)
		// Update repository status to ERROR if repository_name is specified
		if msg.RepositoryName != "" {
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, msg.RepositoryName, err.Error())
		}
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "Got repositories, count=%d, baseURL=%s, target=%s, repository_name=%s",
		len(repos), gitHubSetting.BaseUrl, gitHubSetting.TargetResource, msg.RepositoryName)
	// Filtered By Name
	repos = common.FilterByNamePattern(repos, gitHubSetting.DependencySetting.RepositoryPattern)

	for _, r := range repos {
		isSkip := s.skipScan(ctx, r, s.limitRepositorySizeKb)
		if isSkip {
			continue
		}
		repoFullName := r.GetFullName()

		// Update repository status to IN_PROGRESS
		if err := s.updateRepositoryStatusInProgress(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName); err != nil {
			s.logger.Warnf(ctx, "Failed to update repository status to IN_PROGRESS: repository_name=%s, err=%+v", repoFullName, err)
		}

		// Scan per repository
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

		// Put findings
		if err := s.putFindings(ctx, msg.ProjectID, findings); err != nil {
			s.logger.Errorf(ctx, "failed to put findings: github_setting_id=%d, repository_name=%s, err=%+v", msg.GitHubSettingID, r.GetFullName(), err)
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
			return mimosasqs.WrapNonRetryable(err)
		}

		// Put repository resource
		if err := s.putResource(ctx, msg.ProjectID, *r.FullName); err != nil {
			s.logger.Errorf(ctx, "Failed to put resource: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
			return mimosasqs.WrapNonRetryable(err)
		}

		// Clear score for inactive findings
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

		// Update repository status to OK
		if err := s.updateRepositoryStatusSuccess(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName); err != nil {
			s.logger.Warnf(ctx, "Failed to update repository status success: repository_name=%s, err=%+v", repoFullName, err)
		}
	}
	s.logger.Infof(ctx, "end Scan, RequestID=%s", requestID)
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
