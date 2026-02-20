package gitleaks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
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
	"github.com/zricethezav/gitleaks/v8/report"
)

type sqsHandler struct {
	cipherBlock           cipher.Block
	githubClient          githubcli.GithubServiceClient
	gitleaksClient        gitleaksServiceClient
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
	redact bool,
	gitleaksConfigPath string,
	limitRepositorySizeKb int,
	l logging.Logger,
) (*sqsHandler, error) {
	key := []byte(codeDataKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gitleaksConf := &gitleaksConfig{
		githubDefaultToken: githubDefaultToken,
		redact:             redact,
		configPath:         gitleaksConfigPath,
	}
	return &sqsHandler{
		cipherBlock:           block,
		githubClient:          githubcli.NewGithubClient(githubDefaultToken, l),
		gitleaksClient:        newGitleaksClient(gitleaksConf),
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
	token, err := codecrypto.DecryptWithBase64(&s.cipherBlock, gitHubSetting.PersonalAccessToken)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to decrypt personal access token: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	gitHubSetting.PersonalAccessToken = token // Set the plaintext so that the value is still decipherable next processes.

	messageRepos := getRepositoriesFromCodeQueueMessage(msg)

	if err := s.handleRepositoryScan(ctx, msg, gitHubSetting, token, requestID, messageRepos); err != nil {
		return err
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

func (s *sqsHandler) skipScan(ctx context.Context, repo *github.Repository, lastScannedAt *time.Time, limitRepositorySize int) bool {
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

	// Check comparing pushedAt and lastScannedAt
	if repo.PushedAt != nil && lastScannedAt != nil && repo.PushedAt.Unix() <= lastScannedAt.Unix() {
		s.logger.Infof(ctx, "Skip scan for %s repository(already scanned)", repoName)
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
	if data == nil || data.GithubSetting == nil || data.GithubSetting.GitleaksSetting == nil {
		return nil, fmt.Errorf("no data for scan gitleaks, project_id=%d, github_setting_id=%d", projectID, GitHubSettingID)
	}
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
	resp, err := s.codeClient.PutGitleaksRepository(ctx, &code.PutGitleaksRepositoryRequest{
		ProjectId: projectID,
		GitleaksRepository: &code.GitleaksRepositoryForUpsert{
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
	s.logger.Infof(ctx, "Success to update gitleaks repository status, repository=%s, status=%v, response=%+v", repositoryFullName, status, resp)
	return nil
}

func (s *sqsHandler) updateRepositoryStatusErrorWithWarn(ctx context.Context, projectID, githubSettingID uint32, repositoryFullName, statusDetail string) {
	if err := s.updateRepositoryStatusError(ctx, projectID, githubSettingID, repositoryFullName, statusDetail); err != nil {
		s.logger.Warnf(ctx, "Failed to update repository status error: repository_name=%s, err=%+v", repositoryFullName, err)
	}
}

func (s *sqsHandler) handleRepositoryScan(ctx context.Context, msg *message.CodeQueueMessage, gitHubSetting *code.GitHubSetting, token string, requestID string, messageRepos []*github.Repository) error {
	repos := messageRepos
	if len(repos) == 0 {
		return mimosasqs.WrapNonRetryable(fmt.Errorf("repository metadata is required in queue message"))
	}
	s.logger.Infof(ctx, "Repository source=queue_message, count=%d, request_id=%s", len(repos), requestID)
	if msg.RepositoryName != "" {
		repoFullName := repos[0].GetFullName()
		if repoFullName != msg.RepositoryName {
			return mimosasqs.WrapNonRetryable(fmt.Errorf("repository_name does not match repository.full_name in queue message: repository_name=%s, repository_full_name=%s", msg.RepositoryName, repoFullName))
		}
	}
	if err := validateRepositoriesForFilter(repos); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "Got repositories, count=%d, baseURL=%s, target=%s, repository_pattern=%s, repository_name=%s",
		len(repos), gitHubSetting.BaseUrl, gitHubSetting.TargetResource, gitHubSetting.GitleaksSetting.RepositoryPattern, msg.RepositoryName)
	// Filtered By Visibility
	repos = common.FilterByVisibility(repos, gitHubSetting.GitleaksSetting.ScanPublic, gitHubSetting.GitleaksSetting.ScanInternal, gitHubSetting.GitleaksSetting.ScanPrivate)
	// Filtered By Name
	repos = common.FilterByNamePattern(repos, gitHubSetting.GitleaksSetting.RepositoryPattern)

	return s.scanDiffRepositories(ctx, msg, token, repos)
}

func (s *sqsHandler) scanDiffRepositories(ctx context.Context, msg *message.CodeQueueMessage, token string, repos []*github.Repository) error {
	for _, r := range repos {
		if err := validateRepositoryForScan(r); err != nil {
			repoFullName := ""
			if r != nil {
				repoFullName = r.GetFullName()
			}
			if repoFullName != "" {
				s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
			}
			return mimosasqs.WrapNonRetryable(err)
		}
		// Get LastScannedAt
		var lastScannedAt *time.Time
		if !msg.FullScan {
			var err error
			lastScannedAt, err = s.getLastScannedAt(ctx, msg.ProjectID, msg.GitHubSettingID, r.GetFullName())
			if err != nil {
				repoFullName := r.GetFullName()
				s.logger.Errorf(ctx, "Failed to get LastScannedAt: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
				s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
				return mimosasqs.WrapNonRetryable(err)
			}
		}

		if s.skipScan(ctx, r, lastScannedAt, s.limitRepositorySizeKb) {
			continue
		}

		repoFullName := r.GetFullName()

		// Update repository status to IN_PROGRESS
		if err := s.updateRepositoryStatusInProgress(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName); err != nil {
			s.logger.Warnf(ctx, "Failed to update repository status to IN_PROGRESS: repository_name=%s, err=%+v", repoFullName, err)
		}

		// Scan per repository
		results, err := s.scanRepository(ctx, r, token, lastScannedAt, msg)
		if err != nil {
			s.logger.Errorf(ctx, "Failed to scan repositories: github_setting_id=%d, repository_name=%s, err=%+v", msg.GitHubSettingID, repoFullName, err)
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
			return mimosasqs.WrapNonRetryable(err)
		}

		// Put Resource
		if len(results) == 0 {
			if err := s.putResource(ctx, msg.ProjectID, repoFullName); err != nil {
				s.logger.Errorf(ctx, "Failed to put resource: github_setting_id=%d, repository_name=%s, err=%+v", msg.GitHubSettingID, repoFullName, err)
				s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
				return mimosasqs.WrapNonRetryable(err)
			}
			if err := s.updateRepositoryStatusSuccess(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName); err != nil {
				s.logger.Warnf(ctx, "Failed to update repository status success: repository_name=%s, err=%+v", repoFullName, err)
			}
			continue
		}

		// Put findings
		if err := s.putFindings(ctx, msg.ProjectID, GenrateGitleaksFinding(r, results)); err != nil {
			s.logger.Errorf(ctx, "failed to put findings: github_setting_id=%d, repository_name=%s, err=%+v", msg.GitHubSettingID, repoFullName, err)
			s.updateRepositoryStatusErrorWithWarn(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName, err.Error())
			return mimosasqs.WrapNonRetryable(err)
		}

		// Update repository status to OK
		if err := s.updateRepositoryStatusSuccess(ctx, msg.ProjectID, msg.GitHubSettingID, repoFullName); err != nil {
			s.logger.Warnf(ctx, "Failed to update repository status success: repository_name=%s, err=%+v", repoFullName, err)
		}
	}
	return nil
}

func (s *sqsHandler) scanRepository(ctx context.Context, r *github.Repository, token string, lastScannedAt *time.Time, msg *message.CodeQueueMessage) ([]report.Finding, error) {
	// Clone repository
	dir, err := common.CreateCloneDir(*r.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create directory to clone %s: %w", *r.FullName, err)
	}
	defer os.RemoveAll(dir)

	cloneDate := time.Now()
	err = s.githubClient.Clone(ctx, token, *r.CloneURL, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to clone %s: %w", *r.FullName, err)
	}

	// Scan repository
	from := r.CreatedAt.Time
	if lastScannedAt != nil {
		from = *lastScannedAt
	}
	duration := getScanDuration(from, r.PushedAt.Time)
	results, err := s.gitleaksClient.scan(ctx, dir, duration)
	if err != nil {
		return nil, fmt.Errorf("failed to scan %s: %w", *r.FullName, err)
	}

	// Caching scanned time
	if _, err := s.codeClient.PutGitleaksCache(ctx, &code.PutGitleaksCacheRequest{
		ProjectId: msg.ProjectID,
		GitleaksCache: &code.GitleaksCacheForUpsert{
			GithubSettingId:    msg.GitHubSettingID,
			RepositoryFullName: *r.FullName,
			ScanAt:             cloneDate.Unix(),
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to cache time %s: %w", *r.FullName, err)
	}
	return results, nil
}

func (s *sqsHandler) putResource(ctx context.Context, projectID uint32, resourceName string) error {
	resp, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
		ProjectId: projectID,
		Resource: &finding.ResourceForUpsert{
			ResourceName: resourceName,
			ProjectId:    projectID,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to put resource: project_id=%d, resource_name=%s, err=%w", projectID, resourceName, err)
	}
	for _, t := range []string{tagCode, tagRipository} {
		err = s.tagResource(ctx, t, resp.Resource.ResourceId, projectID)
		if err != nil {
			return err
		}
	}
	s.logger.Debugf(ctx, "Success to PutResource, resource_id=%d", resp.Resource.ResourceId)
	return nil
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, findings []*GitleaksFinding) error {
	// Exists leaks
	for _, f := range findings {
		if f == nil || f.Result == nil {
			s.logger.Warnf(ctx, "Skip put finding because of invalid data, project_id=%d, finding=%+v", projectID, f)
			continue
		}
		// finding
		req, err := GeneratePutFindingRequest(projectID, f)
		if err != nil {
			return err
		}
		resp, err := s.findingClient.PutFinding(ctx, req)
		if err != nil {
			return err
		}
		// finding-tag
		for _, t := range []string{tagCode, tagRipository, tagGitleaks, *f.Visibility, *f.FullName} {
			err = s.tagFinding(ctx, t, resp.Finding.FindingId, resp.Finding.ProjectId)
			if err != nil {
				return err
			}
		}
		if len(f.Result.Tags) > 0 {
			for _, tag := range f.Result.Tags {
				err = s.tagFinding(ctx, strings.TrimSpace(tag), resp.Finding.FindingId, resp.Finding.ProjectId)
				if err != nil {
					return err
				}
			}
		}
		recommendContent := GetRecommend(
			f.Result.RuleDescription,
			f.Result.Repo,
			f.Result.File,
			*f.Visibility,
			f.Result.URL,
			f.Result.Author,
			f.Result.Email,
		)
		recommendTypeStr := fmt.Sprintf("%s-%s-%s-%s-%d-%d-%d", f.Result.RuleDescription, f.Result.Repo, f.Result.Commit, f.Result.File, f.Result.StartLine, f.Result.EndLine, f.Result.StartColumn)
		recommendTypeBytes := sha256.Sum256([]byte(recommendTypeStr))
		recommendType := hex.EncodeToString(recommendTypeBytes[:])
		err = s.putRecommend(ctx, resp.Finding.ProjectId, resp.Finding.FindingId, recommendType, recommendContent)
		if err != nil {
			return err
		}
		s.logger.Debugf(ctx, "Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	}
	return nil
}

func (s *sqsHandler) getLastScannedAt(ctx context.Context, projectID, githubSettingID uint32, repoName string) (*time.Time, error) {
	cache, err := s.codeClient.GetGitleaksCache(ctx, &code.GetGitleaksCacheRequest{
		ProjectId:          projectID,
		GithubSettingId:    githubSettingID,
		RepositoryFullName: repoName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get gitleaks cache, project_id=%d, repository=%s, err=%w", projectID, repoName, err)
	}
	if cache != nil && cache.GitleaksCache != nil && cache.GitleaksCache.ScanAt != 0 {
		lastScannedAt := time.Unix(cache.GitleaksCache.ScanAt, 0)
		return &lastScannedAt, nil
	}

	s.logger.Infof(ctx, "No repository cache: %s", repoName)
	return nil, nil
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
		return fmt.Errorf("failed to TagFinding, finding_id=%d, tag=%s, error=%w", findingID, tag, err)
	}
	return nil
}

func (s *sqsHandler) tagResource(ctx context.Context, tag string, resourceID uint64, projectID uint32) error {
	if _, err := s.findingClient.TagResource(ctx, &finding.TagResourceRequest{
		ProjectId: projectID,
		Tag: &finding.ResourceTagForUpsert{
			ResourceId: resourceID,
			ProjectId:  projectID,
			Tag:        tag,
		}}); err != nil {
		return fmt.Errorf("failed to TagResource, resource_id=%d, tag=%s, error=%w", resourceID, tag, err)
	}
	return nil
}

func (s *sqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, rule string, r *Recommend) error {
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     message.GitleaksDataSource,
		Type:           rule,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		return fmt.Errorf("failed to PutRecommend, finding_id=%d, rule=%s, error=%w", findingID, rule, err)
	}
	return nil
}

func sanitizeStatusDetail(status code.Status, statusDetail string) string {
	if status != code.Status_ERROR {
		return statusDetail
	}
	statusDetail = strings.ToValidUTF8(statusDetail, "")
	statusDetail = common.CutString(statusDetail, 200)
	// Re-sanitize after CutString to prevent invalid UTF-8 from byte-level truncation
	return strings.ToValidUTF8(statusDetail, "")
}

func getRepositoriesFromCodeQueueMessage(msg *message.CodeQueueMessage) []*github.Repository {
	if msg == nil || msg.Repository == nil {
		return nil
	}
	repoMeta := msg.Repository
	size := int(repoMeta.Size)
	repo := &github.Repository{
		Name:       github.String(repoMeta.Name),
		FullName:   github.String(repoMeta.FullName),
		CloneURL:   github.String(repoMeta.CloneURL),
		Visibility: github.String(repoMeta.Visibility),
		Archived:   github.Bool(repoMeta.Archived),
		Fork:       github.Bool(repoMeta.Fork),
		Disabled:   github.Bool(repoMeta.Disabled),
		Size:       &size,
		HTMLURL:    github.String(repoMeta.HTMLURL),
	}
	if repoMeta.CreatedAt != 0 {
		repo.CreatedAt = &github.Timestamp{Time: time.Unix(repoMeta.CreatedAt, 0)}
	}
	if repoMeta.PushedAt != 0 {
		repo.PushedAt = &github.Timestamp{Time: time.Unix(repoMeta.PushedAt, 0)}
	}
	return []*github.Repository{repo}
}


