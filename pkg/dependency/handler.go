package dependency

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
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
	dependencyClient      dependencyServiceClient
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
		githubDefaultToken: githubDefaultToken,
		trivyPath:          trivyPath,
	}
	return &sqsHandler{
		cipherBlock:           block,
		dependencyClient:      newDependencyClient(ctx, dependencyConf),
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

	beforeScanAt := time.Now()
	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}
	s.logger.Infof(ctx, "start Scan, RequestID=%s", requestID)
	gitHubSetting, err := s.getGitHubSetting(ctx, msg.ProjectID, msg.GitHubSettingID)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get scan status: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	scanStatus := s.initScanStatus(gitHubSetting.DependencySetting)

	// Get repositories
	repos, err := s.githubClient.ListRepository(ctx, gitHubSetting)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to list repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "Got repositories, count=%d, baseURL=%s, target=%s",
		len(repos), gitHubSetting.BaseUrl, gitHubSetting.TargetResource)

	for _, r := range repos {
		isSkip := s.skipScan(ctx, r, s.limitRepositorySizeKb)
		if isSkip {
			continue
		}

		// Scan per repository
		resultFilePath := fmt.Sprintf("/tmp/%v_%v_%s_%v.json", msg.ProjectID, msg.GitHubSettingID, *r.Name, time.Now().Unix())
		result, err := s.dependencyClient.getResult(ctx, *r.CloneURL, gitHubSetting.PersonalAccessToken, resultFilePath)
		if err != nil {
			s.logger.Errorf(ctx, "Failed to scan repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}

		findings, err := makeFindings(msg, result, r.GetID())
		if err != nil {
			s.logger.Errorf(ctx, "Failed to make findings: github_setting_id=%d, repository_name=%s, err=%+v", msg.GitHubSettingID, r.GetFullName(), err)
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}

		// Put findings
		if err := s.putFindings(ctx, msg.ProjectID, findings); err != nil {
			s.logger.Errorf(ctx, "failed to put findings: github_setting_id=%d, repository_name=%s, err=%+v", msg.GitHubSettingID, r.GetFullName(), err)
			s.updateStatusToError(ctx, scanStatus, err)
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
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}
	}
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
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

func (s *sqsHandler) updateStatusToError(ctx context.Context, scanStatus *code.PutDependencySettingRequest, err error) {
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

func (s *sqsHandler) initScanStatus(g *code.DependencySetting) *code.PutDependencySettingRequest {
	return &code.PutDependencySettingRequest{
		ProjectId: g.ProjectId,
		DependencySetting: &code.DependencySettingForUpsert{
			GithubSettingId:  g.GithubSettingId,
			CodeDataSourceId: g.CodeDataSourceId,
			ProjectId:        g.ProjectId,
			ScanAt:           time.Now().Unix(),
			Status:           code.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:     "",
		},
	}
}

func (s *sqsHandler) updateScanStatusError(ctx context.Context, putData *code.PutDependencySettingRequest, statusDetail string) error {
	putData.DependencySetting.Status = code.Status_ERROR
	statusDetail = cutString(statusDetail, 200)
	putData.DependencySetting.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, putData *code.PutDependencySettingRequest) error {
	putData.DependencySetting.Status = code.Status_OK
	putData.DependencySetting.StatusDetail = ""
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatus(ctx context.Context, putData *code.PutDependencySettingRequest) error {
	resp, err := s.codeClient.PutDependencySetting(ctx, putData)
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

func cutString(input string, cut int) string {
	if len(input) > cut {
		return input[:cut] + " ..." // cut long text
	}
	return input
}
