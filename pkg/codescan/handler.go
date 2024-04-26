package codescan

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
	"strings"
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

	beforeScanAt := time.Now()
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
	scanStatus := s.initScanStatus((gitHubSetting.CodeScanSetting))

	// Get repositories
	repos, err := s.githubClient.ListRepository(ctx, gitHubSetting)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to list repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "Got repositories, count=%d, baseURL=%s, target=%s",
		len(repos), gitHubSetting.BaseUrl, gitHubSetting.TargetResource)
	// Filtered By Visibility
	repos = filterByVisibility(repos, gitHubSetting.CodeScanSetting.ScanPublic, gitHubSetting.CodeScanSetting.ScanInternal, gitHubSetting.CodeScanSetting.ScanPrivate)
	// Filtered By Name
	repos = filterByNamePattern(repos, gitHubSetting.CodeScanSetting.RepositoryPattern)

	semgrepFindings := []*SemgrepFinding{}
	for _, r := range repos {
		if s.skipScan(ctx, r, s.limitRepositorySizeKb) {
			continue
		}

		// Scan source code
		scanResult, err := s.scanForRepository(ctx, r, token, gitHubSetting.BaseUrl)
		if err != nil {
			s.logger.Errorf(ctx, "failed to codeScan scan: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}
		semgrepFindings = append(semgrepFindings, scanResult...)
	}
	if err := s.putSemgrepFindings(ctx, msg.ProjectID, semgrepFindings); err != nil {
		s.logger.Errorf(ctx, "failed to put findings: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		s.updateStatusToError(ctx, scanStatus, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	// Clear score for inactive findings
	for _, r := range repos {
		repo := r.GetFullName()
		if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
			DataSource: message.GoogleCloudSploitDataSource,
			ProjectId:  msg.ProjectID,
			Tag:        []string{tagCodeScan, repo},
			BeforeAt:   beforeScanAt.Unix(),
		}); err != nil {
			s.logger.Errorf(ctx, "Failed to clear finding score. project_id: %v, repo: %s, error: %v", msg.ProjectID, repo, err)
			s.updateStatusToError(ctx, scanStatus, err)
			return mimosasqs.WrapNonRetryable(err)
		}
	}

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
	statusDetail = cutString(statusDetail, 200)
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

func filterByNamePattern(repos []*github.Repository, pattern string) []*github.Repository {
	var filteredRepos []*github.Repository
	for _, repo := range repos {
		if strings.Contains(*repo.Name, pattern) {
			filteredRepos = append(filteredRepos, repo)
		}
	}

	return filteredRepos
}

const (
	githubVisibilityPublic   string = "public"
	githubVisibilityInternal string = "internal"
	githubVisibilityPrivate  string = "private"
)

func filterByVisibility(repos []*github.Repository, scanPublic, scanInternal, scanPrivate bool) []*github.Repository {
	var filteredRepos []*github.Repository
	for _, repo := range repos {
		if scanPublic && *repo.Visibility == githubVisibilityPublic {
			filteredRepos = append(filteredRepos, repo)
		}
		if scanInternal && *repo.Visibility == githubVisibilityInternal {
			filteredRepos = append(filteredRepos, repo)
		}
		if scanPrivate && *repo.Visibility == githubVisibilityPrivate {
			filteredRepos = append(filteredRepos, repo)
		}
	}
	return filteredRepos
}

func cutString(input string, cut int) string {
	if len(input) > cut {
		return input[:cut] + " ..." // cut long text
	}
	return input
}

func createCloneDir(repoName string) (string, error) {
	if repoName == "" {
		return "", errors.New("invalid value: repoName is not empty")
	}

	dir, err := os.MkdirTemp("", repoName)
	if err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}
	return dir, nil
}
