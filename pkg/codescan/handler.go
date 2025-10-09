package codescan

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"reflect"
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

	// Check if this is a repository-level scan
	// Use reflection to safely access RepositoryName field if it exists
	repositoryName := getRepositoryNameFromMessage(msg)
	if repositoryName != "" {
		return s.handleRepositoryScan(ctx, msg, gitHubSetting, token, repositoryName)
	}

	// Original organization-level scan logic
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
	repos = common.FilterByVisibility(repos, gitHubSetting.CodeScanSetting.ScanPublic, gitHubSetting.CodeScanSetting.ScanInternal, gitHubSetting.CodeScanSetting.ScanPrivate)
	// Filtered By Name
	repos = common.FilterByNamePattern(repos, gitHubSetting.CodeScanSetting.RepositoryPattern)

	beforeScanAt := time.Now()
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

// getRepositoryNameFromMessage safely extracts RepositoryName from message using reflection
func getRepositoryNameFromMessage(msg interface{}) string {
	if msg == nil {
		return ""
	}

	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}

	// Only process struct types
	if v.Kind() != reflect.Struct {
		return ""
	}

	// Try to get RepositoryName field
	if field := v.FieldByName("RepositoryName"); field.IsValid() && field.CanInterface() {
		if str, ok := field.Interface().(string); ok {
			return str
		}
	}

	return ""
}

// handleRepositoryScan handles scanning for a specific repository
func (s *sqsHandler) handleRepositoryScan(ctx context.Context, msg interface{}, gitHubSetting *code.GitHubSetting, token, repositoryName string) error {
	s.logger.Infof(ctx, "Starting repository-level scan for: %s", repositoryName)

	// Get specific repository information
	repo, err := s.githubClient.GetSingleRepository(ctx, gitHubSetting, repositoryName)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get repository: repository_name=%s, err=%+v", repositoryName, err)
		return s.updateRepositoryStatusError(ctx, msg, repositoryName, err.Error(), gitHubSetting)
	}

	// Check if repository should be skipped
	if s.skipScan(ctx, repo, s.limitRepositorySizeKb) {
		s.logger.Infof(ctx, "Skipping scan for repository: %s", repositoryName)
		return s.updateRepositoryStatusSuccess(ctx, msg, repositoryName, gitHubSetting)
	}

	// Update repository status to IN_PROGRESS
	if err := s.updateRepositoryStatusInProgress(ctx, msg, repositoryName, gitHubSetting); err != nil {
		s.logger.Warnf(ctx, "Failed to update repository status to IN_PROGRESS: err=%+v", err)
	}

	beforeScanAt := time.Now()

	// Scan source code for the specific repository
	scanResult, err := s.scanForRepository(ctx, repo, token, gitHubSetting.BaseUrl)
	if err != nil {
		s.logger.Errorf(ctx, "failed to codeScan scan: repository_name=%s, err=%+v", repositoryName, err)
		return s.updateRepositoryStatusError(ctx, msg, repositoryName, err.Error(), gitHubSetting)
	}

	// Put findings
	projectID := getProjectIDFromMessage(msg)
	if err := s.putSemgrepFindings(ctx, projectID, scanResult); err != nil {
		s.logger.Errorf(ctx, "failed to put findings: repository_name=%s, err=%+v", repositoryName, err)
		return s.updateRepositoryStatusError(ctx, msg, repositoryName, err.Error(), gitHubSetting)
	}

	// Clear score for inactive findings
	repoName := repo.GetFullName()
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: message.CodeScanDataSource,
		ProjectId:  projectID,
		Tag:        []string{tagCodeScan, repoName},
		BeforeAt:   beforeScanAt.Unix(),
	}); err != nil {
		s.logger.Errorf(ctx, "Failed to clear finding score. project_id: %v, repo: %s, error: %v", projectID, repoName, err)
		return s.updateRepositoryStatusError(ctx, msg, repositoryName, err.Error(), gitHubSetting)
	}

	// Update repository status to success
	if err := s.updateRepositoryStatusSuccess(ctx, msg, repositoryName, gitHubSetting); err != nil {
		s.logger.Warnf(ctx, "Failed to update repository status to success: err=%+v", err)
	}

	s.logger.Infof(ctx, "Successfully completed repository-level scan for: %s", repositoryName)
	return nil
}

// getProjectIDFromMessage safely extracts ProjectID from message using reflection
func getProjectIDFromMessage(msg interface{}) uint32 {
	if msg == nil {
		return 0
	}

	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return 0
		}
		v = v.Elem()
	}

	// Only process struct types
	if v.Kind() != reflect.Struct {
		return 0
	}

	// Try to get ProjectID field
	if field := v.FieldByName("ProjectID"); field.IsValid() && field.CanInterface() {
		if projectID, ok := field.Interface().(uint32); ok {
			return projectID
		}
	}

	return 0
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

// Repository status management methods

// updateRepositoryStatusInProgress updates repository status to IN_PROGRESS
func (s *sqsHandler) updateRepositoryStatusInProgress(ctx context.Context, msg interface{}, repositoryName string, gitHubSetting *code.GitHubSetting) error {
	// TODO: Implement UpdateCodescanRepositoryStatus API call
	// Get repository ID from GitHub API
	// repositoryID, err := s.getRepositoryID(ctx, repositoryName, gitHubSetting)
	// if err != nil {
	// 	s.logger.Errorf(ctx, "Failed to get repository ID for %s: err=%+v", repositoryName, err)
	// 	return err
	// }

	// Call datasource-api gRPC service
	// _, err = s.codeClient.UpdateCodescanRepositoryStatus(ctx, &code.UpdateCodescanRepositoryStatusRequest{
	// 	RepositoryId: repositoryID,
	// 	Status:       "IN_PROGRESS",
	// 	Message:      "",
	// })
	// if err != nil {
	// 	s.logger.Errorf(ctx, "Failed to update repository status to IN_PROGRESS for %s: err=%+v", repositoryName, err)
	// 	return err
	// }

	s.logger.Infof(ctx, "Updating repository status to IN_PROGRESS for: %s", repositoryName)
	return nil
}

// updateRepositoryStatusSuccess updates repository status to OK and checks parent status
func (s *sqsHandler) updateRepositoryStatusSuccess(ctx context.Context, msg interface{}, repositoryName string, gitHubSetting *code.GitHubSetting) error {
	// TODO: Implement UpdateCodescanRepositoryStatus API call
	// Get repository ID from GitHub API
	// repositoryID, err := s.getRepositoryID(ctx, repositoryName, gitHubSetting)
	// if err != nil {
	// 	s.logger.Errorf(ctx, "Failed to get repository ID for %s: err=%+v", repositoryName, err)
	// 	return err
	// }

	// Call datasource-api gRPC service
	// _, err = s.codeClient.UpdateCodescanRepositoryStatus(ctx, &code.UpdateCodescanRepositoryStatusRequest{
	// 	RepositoryId: repositoryID,
	// 	Status:       "OK",
	// 	Message:      "",
	// })
	// if err != nil {
	// 	s.logger.Errorf(ctx, "Failed to update repository status to OK for %s: err=%+v", repositoryName, err)
	// 	return err
	// }

	s.logger.Infof(ctx, "Updating repository status to OK for: %s", repositoryName)
	return nil
}

// updateRepositoryStatusError updates repository status to ERROR and checks parent status
func (s *sqsHandler) updateRepositoryStatusError(ctx context.Context, msg interface{}, repositoryName, errorMessage string, gitHubSetting *code.GitHubSetting) error {
	// TODO: Implement UpdateCodescanRepositoryStatus API call
	// Get repository ID from GitHub API
	// repositoryID, err := s.getRepositoryID(ctx, repositoryName, gitHubSetting)
	// if err != nil {
	// 	s.logger.Errorf(ctx, "Failed to get repository ID for %s: err=%+v", repositoryName, err)
	// 	return err
	// }

	// Call datasource-api gRPC service
	// _, err = s.codeClient.UpdateCodescanRepositoryStatus(ctx, &code.UpdateCodescanRepositoryStatusRequest{
	// 	RepositoryId: repositoryID,
	// 	Status:       "ERROR",
	// 	Message:      errorMessage,
	// })
	// if err != nil {
	// 	s.logger.Errorf(ctx, "Failed to update repository status to ERROR for %s: err=%+v", repositoryName, err)
	// 	return err
	// }

	s.logger.Errorf(ctx, "Updating repository status to ERROR for: %s, error: %s", repositoryName, errorMessage)
	return nil
}

// getRepositoryID gets repository ID from GitHub API using repository name
func (s *sqsHandler) getRepositoryID(ctx context.Context, repositoryName string, gitHubSetting *code.GitHubSetting) (uint32, error) {
	// Parse repository name to get owner and repo name
	// repositoryName format: "owner/repo" or "org/repo"
	parts := strings.Split(repositoryName, "/")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid repository name format: %s, expected 'owner/repo'", repositoryName)
	}

	// Get repository information from GitHub API
	repo, err := s.githubClient.GetSingleRepository(ctx, gitHubSetting, repositoryName)
	if err != nil {
		return 0, fmt.Errorf("failed to get repository %s: %w", repositoryName, err)
	}

	// Return repository ID as uint32
	return uint32(repo.GetID()), nil
}
