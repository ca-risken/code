package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
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
	githubClient          githubServiceClient
	gitleaksClient        gitleaksServiceClient
	findingClient         finding.FindingServiceClient
	alertClient           alert.AlertServiceClient
	codeClient            code.CodeServiceClient
	limitRepositorySizeKb int
}

type gitleaksFinding struct {
	*RepositoryMetadata `json:"repository_metadata,omitempty"`
	Result              *leakFinding `json:"results,omitempty"`
}

type RepositoryMetadata struct {
	ID                  *int64           `json:"id,omitempty"`
	NodeID              *string          `json:"node_id,omitempty"`
	Name                *string          `json:"name,omitempty"`
	FullName            *string          `json:"full_name,omitempty"`
	Description         *string          `json:"description,omitempty"`
	Homepage            *string          `json:"homepage,omitempty"`
	CloneURL            *string          `json:"clone_url,omitempty"`
	GitURL              *string          `json:"git_url,omitempty"`
	MirrorURL           *string          `json:"mirror_url,omitempty"`
	SSHURL              *string          `json:"ssh_url,omitempty"`
	Language            *string          `json:"language,omitempty"`
	Fork                *bool            `json:"fork,omitempty"`
	Size                *int             `json:"size,omitempty"`
	DeleteBranchOnMerge *bool            `json:"delete_branch_on_merge,omitempty"`
	Topics              []string         `json:"topics,omitempty"`
	Archived            *bool            `json:"archived,omitempty"`
	Disabled            *bool            `json:"disabled,omitempty"`
	Permissions         *map[string]bool `json:"permissions,omitempty"`
	Private             *bool            `json:"private,omitempty"`
	TeamID              *int64           `json:"team_id,omitempty"`
	Visibility          *string          `json:"visibility,omitempty"`

	CreatedAt *github.Timestamp `json:"created_at,omitempty"`
	PushedAt  *github.Timestamp `json:"pushed_at,omitempty"`
	UpdatedAt *github.Timestamp `json:"updated_at,omitempty"`

	LeakFindings []*leakFinding `json:"leak_findings,omitempty"`
}

type leakFinding struct {
	DataSourceID string `json:"data_source_id"`

	StartLine       int      `json:"startLine,omitempty"`
	EndLine         int      `json:"endLine,omitempty"`
	StartColumn     int      `json:"startColumn,omitempty"`
	Secret          string   `json:"secret,omitempty"`
	Commit          string   `json:"commit,omitempty"`
	Repo            string   `json:"repo,omitempty"`
	RuleDescription string   `json:"ruleDescription,omitempty"`
	Message         string   `json:"commitMessage,omitempty"`
	Author          string   `json:"author,omitempty"`
	Email           string   `json:"email,omitempty"`
	File            string   `json:"file,omitempty"`
	Date            string   `json:"date,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	URL             string   `json:"url,omitempty"`
}

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getRecommend(rule string) *recommend {
	return &recommend{
		Risk: fmt.Sprintf(`%s
		- If a key is leaked, a cyber attack is possible within the scope of the key's authority
		- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`, rule),
		Recommendation: `Take the following actions for leaked keys
		- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
		- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
		- ... Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
	}
}

func (l *leakFinding) generateDataSourceID() string {
	hash := sha256.Sum256([]byte(l.Repo + l.Commit + l.Secret + l.File + fmt.Sprint(l.StartLine) + fmt.Sprint(l.EndLine) + fmt.Sprint(l.StartColumn)))
	return hex.EncodeToString(hash[:])
}

func (l *leakFinding) generateGitHubURL(repositoryURL string) string {
	url := fmt.Sprintf("%s/blob/%s/%s#L%d-L%d", repositoryURL, l.Commit, l.File, l.StartLine, l.EndLine)
	return url
}

func newHandler(ctx context.Context, conf *AppConfig) (*sqsHandler, error) {
	key := []byte(conf.CodeDataKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gitleaksConf := &gitleaksConfig{
		githubDefaultToken: conf.GithubDefaultToken,
		redact:             conf.Redact,
		configPath:         conf.GitleaksConfigPath,
	}
	findingClient, err := newFindingClient(ctx, conf.CoreSvcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create finding client: %w", err)
	}
	alertClient, err := newAlertClient(ctx, conf.CoreSvcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create alert client: %w", err)
	}
	codeClient, err := newCodeClient(ctx, conf.DataSourceAPISvcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create code client: %w", err)
	}
	return &sqsHandler{
		cipherBlock:           block,
		githubClient:          newGithubClient(gitleaksConf.githubDefaultToken),
		gitleaksClient:        newGitleaksClient(ctx, gitleaksConf),
		findingClient:         findingClient,
		alertClient:           alertClient,
		codeClient:            codeClient,
		limitRepositorySizeKb: conf.LimitRepositorySizeKb,
	}, nil
}

func (s *sqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	appLogger.Infof(ctx, "got message: %s", msgBody)
	msg, err := message.ParseMessageGitHub(msgBody)
	if err != nil {
		appLogger.Errorf(ctx, "Invalid message: msg=%+v, err=%+v", msg, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	requestID, err := appLogger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		appLogger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}
	appLogger.Infof(ctx, "start Scan, RequestID=%s", requestID)

	gitHubSetting, err := s.getGitHubSetting(ctx, msg.ProjectID, msg.GitHubSettingID)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to get scan status: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	token, err := decryptWithBase64(&s.cipherBlock, gitHubSetting.PersonalAccessToken)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to decrypted personal access token: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	gitHubSetting.PersonalAccessToken = token // Set the plaintext so that the value is still decipherable next processes.
	scanStatus := s.initScanStatus(gitHubSetting.GitleaksSetting)

	// Get repositories
	repos, err := s.listRepository(ctx, gitHubSetting)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to list repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
		return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
	}
	appLogger.Infof(ctx, "Got repositories, count=%d, baseURL=%s, target=%s, repository_pattern=%s",
		len(repos), gitHubSetting.BaseUrl, gitHubSetting.TargetResource, gitHubSetting.GitleaksSetting.RepositoryPattern)

	// Filtered By Name
	repos = filterByNamePattern(repos, gitHubSetting.GitleaksSetting.RepositoryPattern)
	for _, r := range repos {
		// Get LastScanedAt
		lastScannedAt, err := s.getLastScanedAt(ctx, msg.ProjectID, *r.FullName)
		if err != nil {
			appLogger.Errorf(ctx, "Failed to get LastScanedAt: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
			return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
		}

		if skipScan(ctx, r, lastScannedAt, s.limitRepositorySizeKb) {
			continue
		}

		// Scan per repository
		results, err := s.scanRepository(ctx, r, token, lastScannedAt)
		if err != nil {
			appLogger.Errorf(ctx, "Failed to scan repositories: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
			return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
		}

		// Put Resource for caching scanned time when len(result) is zero
		if len(results) == 0 {
			if err := s.putResource(ctx, msg.ProjectID, *r.FullName); err != nil {
				appLogger.Errorf(ctx, "Failed to put resource: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
				return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
			}
			continue
		}

		m := genRepositoryMetadata(r)
		var findings []*gitleaksFinding
		for _, rs := range results {
			findings = append(findings, &gitleaksFinding{
				RepositoryMetadata: m,
				Result:             rs,
			})
		}

		// Put findings
		if err := s.putFindings(ctx, msg.ProjectID, findings); err != nil {
			appLogger.Errorf(ctx, "failed to put findngs: github_setting_id=%d, err=%+v", msg.GitHubSettingID, err)
			return s.handleErrorWithUpdateStatus(ctx, scanStatus, err)
		}
	}
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof(ctx, "end Scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		appLogger.Notifyf(ctx, logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *sqsHandler) scanRepository(ctx context.Context, r *github.Repository, token string, lastScannedAt *time.Time) ([]*leakFinding, error) {
	// Clone repository
	dir, err := createCloneDir(*r.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create directory to clone %s: %w", *r.FullName, err)
	}
	defer os.RemoveAll(dir)

	err = s.githubClient.clone(ctx, token, *r.CloneURL, dir)
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

	var leaks []*leakFinding
	for _, rs := range results {
		l := leakFinding{
			StartColumn:     rs.StartColumn,
			StartLine:       rs.StartLine,
			EndLine:         rs.EndLine,
			Commit:          rs.Commit,
			Secret:          rs.Secret,
			Repo:            *r.FullName,
			RuleDescription: rs.Description,
			Message:         rs.Message,
			Author:          rs.Author,
			Email:           rs.Email,
			File:            rs.File,
			Date:            rs.Date,
			Tags:            rs.Tags,
		}
		l.DataSourceID = l.generateDataSourceID()
		l.URL = l.generateGitHubURL(*r.HTMLURL)
		leaks = append(leaks, &l)
	}

	return leaks, nil
}

func skipScan(ctx context.Context, repo *github.Repository, lastScannedAt *time.Time, limitRepositorySize int) bool {
	if repo == nil {
		appLogger.Warnf(ctx, "Skip scan repository(data not found)")
		return true
	}

	repoName := ""
	if repo.FullName != nil {
		repoName = *repo.FullName
	}
	if repo.Archived != nil && *repo.Archived {
		appLogger.Infof(ctx, "Skip scan for %s repository(archived)", repoName)
		return true
	}
	if repo.Fork != nil && *repo.Fork {
		appLogger.Infof(ctx, "Skip scan for %s repository(fork repo)", repoName)
		return true
	}
	if repo.Disabled != nil && *repo.Disabled {
		appLogger.Infof(ctx, "Skip scan for %s repository(disabled)", repoName)
		return true
	}
	if repo.Size != nil && *repo.Size < 1 {
		appLogger.Infof(ctx, "Skip scan for %s repository(empty)", repoName)
		return true
	}

	// Hard limit size
	if repo.Size != nil && *repo.Size > limitRepositorySize {
		appLogger.Warnf(ctx, "Skip scan for %s repository(too big size, limit=%dkb, size(kb)=%dkb)", repoName, limitRepositorySize, *repo.Size)
		return true
	}

	// Check comparing pushedAt and lastScanedAt
	if repo.PushedAt != nil && lastScannedAt != nil && repo.PushedAt.Time.Unix() <= lastScannedAt.Unix() {
		appLogger.Infof(ctx, "Skip scan for %s repository(already scanned)", repoName)
		return true
	}

	return false
}

func (s *sqsHandler) handleErrorWithUpdateStatus(ctx context.Context, scanStatus *code.PutGitleaksSettingRequest, err error) error {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		appLogger.Warnf(ctx, "Failed to update scan status error: err=%+v", updateErr)
	}
	return mimosasqs.WrapNonRetryable(err)
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

func (s *sqsHandler) initScanStatus(g *code.GitleaksSetting) *code.PutGitleaksSettingRequest {
	return &code.PutGitleaksSettingRequest{
		ProjectId: g.ProjectId,
		GitleaksSetting: &code.GitleaksSettingForUpsert{
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

func (s *sqsHandler) listRepository(ctx context.Context, config *code.GitHubSetting) ([]*github.Repository, error) {
	var repos []*github.Repository
	var err error

	switch config.Type {
	case code.Type_ENTERPRISE:
		repos, err = s.listRepositoryEnterprise(ctx, config)
		if err != nil {
			return nil, err
		}
	case code.Type_ORGANIZATION, code.Type_USER:
		repos, err = s.githubClient.listRepository(ctx, config)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("Unknown github type: type=%+v", config.Type)
	}

	return repos, err
}

func (s *sqsHandler) listRepositoryEnterprise(ctx context.Context, config *code.GitHubSetting) ([]*github.Repository, error) {
	list, err := s.listEnterpriseOrg(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to list enterprise org: %w", err)
	}

	var repos []*github.Repository
	if list != nil {
		for _, org := range list.GithubEnterpriseOrg {
			config.Type = code.Type_ORGANIZATION
			config.TargetResource = org.Organization
			repo, err := s.githubClient.listRepository(ctx, config)
			if err != nil {
				// Enterprise配下のOrgがうまく取得できない場合（クローズ済みなど）もあるため、WARNログ吐いて握りつぶす
				appLogger.Warnf(ctx, "Failed to ListRepository by enterprise, org=%s, err=%+v", org.Organization, err)
				continue
			}
			repos = append(repos, repo...)
		}
	}

	return repos, nil
}

func (s *sqsHandler) listEnterpriseOrg(ctx context.Context, config *code.GitHubSetting) (*code.ListGitHubEnterpriseOrgResponse, error) {
	orgs, err := s.githubClient.listGitHubEnterpriseOrg(ctx, config, config.TargetResource)
	if err != nil {
		return &code.ListGitHubEnterpriseOrgResponse{}, err
	}
	existsOrgMap := make(map[string]bool)
	// update enterprise orgs
	for _, org := range orgs {
		existsOrgMap[org.Login] = true
		if _, err := s.codeClient.PutGitHubEnterpriseOrg(ctx, &code.PutGitHubEnterpriseOrgRequest{
			ProjectId: config.ProjectId,
			GithubEnterpriseOrg: &code.GitHubEnterpriseOrgForUpsert{
				GithubSettingId: config.GithubSettingId,
				Organization:    org.Login,
				ProjectId:       config.ProjectId,
			},
		}); err != nil {
			appLogger.Errorf(ctx, "Failed to PutEnterpriseOrg API, err=%+v", err)
			return &code.ListGitHubEnterpriseOrgResponse{}, err
		}
	}

	// delete enterprise orgs
	if len(orgs) > 0 {
		list, err := s.codeClient.ListGitHubEnterpriseOrg(ctx, &code.ListGitHubEnterpriseOrgRequest{
			ProjectId:       config.ProjectId,
			GithubSettingId: config.GithubSettingId,
		})
		if err != nil {
			appLogger.Errorf(ctx, "Failed to ListEnterpriseOrg API, err=%+v", err)
			return &code.ListGitHubEnterpriseOrgResponse{}, err
		}
		for _, org := range list.GithubEnterpriseOrg {
			if _, ok := existsOrgMap[org.Organization]; ok {
				continue
			}
			if _, err := s.codeClient.DeleteGitHubEnterpriseOrg(ctx, &code.DeleteGitHubEnterpriseOrgRequest{
				ProjectId:       config.ProjectId,
				GithubSettingId: config.GithubSettingId,
				Organization:    org.Organization,
			}); err != nil {
				appLogger.Errorf(ctx, "Failed to DeleteEnterpriseOrg API, err=%+v", err)
				return &code.ListGitHubEnterpriseOrgResponse{}, err
			}
		}
	}
	updatedList, err := s.codeClient.ListGitHubEnterpriseOrg(ctx, &code.ListGitHubEnterpriseOrgRequest{
		ProjectId:       config.ProjectId,
		GithubSettingId: config.GithubSettingId,
	})
	if err != nil {
		appLogger.Errorf(ctx, "Failed to ListEnterpriseOrg API, err=%+v", err)
		return &code.ListGitHubEnterpriseOrgResponse{}, err
	}
	return updatedList, nil
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
		return fmt.Errorf("failed to put resource: project_id=%d, resource_name=%s", projectID, resourceName)
	}
	s.tagResource(ctx, tagCode, resp.Resource.ResourceId, projectID)
	s.tagResource(ctx, tagRipository, resp.Resource.ResourceId, projectID)
	appLogger.Debugf(ctx, "Success to PutResource, resource_id=%d", resp.Resource.ResourceId)
	return nil
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, findings []*gitleaksFinding) error {
	// Exists leaks
	for _, f := range findings {
		// finding
		buf, err := json.Marshal(f)
		if err != nil {
			return fmt.Errorf("failed to marshal user data: project_id=%d, repository=%s, err=%w", projectID, *f.FullName, err)
		}
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
			Finding: &finding.FindingForUpsert{
				Description:      fmt.Sprintf("Secrets scanning by Gitleaks for %s", *f.FullName),
				DataSource:       message.GitleaksDataSource,
				DataSourceId:     f.Result.DataSourceID,
				ResourceName:     *f.FullName,
				ProjectId:        projectID,
				OriginalScore:    defaultGitleaksScore,
				OriginalMaxScore: 1.0,
				Data:             string(buf),
			},
		})
		if err != nil {
			return err
		}
		// finding-tag
		s.tagFinding(ctx, tagCode, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, tagRipository, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, tagGitleaks, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, *f.Visibility, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, *f.FullName, resp.Finding.FindingId, resp.Finding.ProjectId)
		if len(f.Result.Tags) > 0 {
			for _, tag := range f.Result.Tags {
				s.tagFinding(ctx, strings.TrimSpace(tag), resp.Finding.FindingId, resp.Finding.ProjectId)
			}
		}
		s.putRecommend(ctx, resp.Finding.ProjectId, resp.Finding.FindingId, f.Result.RuleDescription)
		appLogger.Debugf(ctx, "Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	}
	return nil
}

const unix99991231T235959 int64 = 253402268399

func (s *sqsHandler) getLastScanedAt(ctx context.Context, projectID uint32, repoName string) (*time.Time, error) {
	resp, err := s.findingClient.ListResource(ctx, &finding.ListResourceRequest{
		ProjectId:    projectID,
		ResourceName: []string{repoName},
		ToAt:         unix99991231T235959,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list resources, project_id=%d, repository=%s, err=%w", projectID, repoName, err)
	}

	for _, id := range resp.ResourceId {
		resp2, err := s.findingClient.GetResource(ctx, &finding.GetResourceRequest{
			ProjectId:  projectID,
			ResourceId: id,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get resources, project_id=%d, repository=%s, err=%w", projectID, repoName, err)
		}
		appLogger.Debugf(ctx, "Got resource: %+v", resp2)
		if resp2 != nil && resp2.Resource != nil && resp2.Resource.ResourceName == repoName {
			lastScannedAt := time.Unix(resp2.Resource.UpdatedAt, 0)
			return &lastScannedAt, nil
		}
	}

	appLogger.Infof(ctx, "No resource registerd: %s", repoName)
	return nil, nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, tag string, findingID uint64, projectID uint32) {
	_, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}})
	if err != nil {
		appLogger.Errorf(ctx, "Failed to TagFinding, finding_id=%d, tag=%s, error=%+v", findingID, tag, err)
	}
}

func (s *sqsHandler) tagResource(ctx context.Context, tag string, resourceID uint64, projectID uint32) {
	if _, err := s.findingClient.TagResource(ctx, &finding.TagResourceRequest{
		ProjectId: projectID,
		Tag: &finding.ResourceTagForUpsert{
			ResourceId: resourceID,
			ProjectId:  projectID,
			Tag:        tag,
		}}); err != nil {
		appLogger.Errorf(ctx, "Failed to TagResource, resource_id=%d, tag=%s, error=%+v", resourceID, tag, err)
	}
}

func (s *sqsHandler) updateScanStatusError(ctx context.Context, putData *code.PutGitleaksSettingRequest, statusDetail string) error {
	putData.GitleaksSetting.Status = code.Status_ERROR
	statusDetail = cutString(statusDetail, 200)
	putData.GitleaksSetting.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, putData *code.PutGitleaksSettingRequest) error {
	putData.GitleaksSetting.Status = code.Status_OK
	putData.GitleaksSetting.StatusDetail = ""
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatus(ctx context.Context, putData *code.PutGitleaksSettingRequest) error {
	resp, err := s.codeClient.PutGitleaksSetting(ctx, putData)
	if err != nil {
		return err
	}
	appLogger.Infof(ctx, "Success to update scan status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

func (s *sqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, rule string) {
	r := *getRecommend(rule)
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     message.GitleaksDataSource,
		Type:           rule,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		appLogger.Errorf(ctx, "Failed to TagFinding, finding_id=%d, rule=%s, error=%+v", findingID, rule, err)
	}
	appLogger.Debugf(ctx, "Success PutRecommend, finding_id=%d, reccomend=%+v", findingID, r)
}

func genRepositoryMetadata(repo *github.Repository) *RepositoryMetadata {
	return &RepositoryMetadata{
		ID:                  repo.ID,
		NodeID:              repo.NodeID,
		Name:                repo.Name,
		FullName:            repo.FullName,
		Description:         repo.Description,
		Homepage:            repo.Homepage,
		CloneURL:            repo.CloneURL,
		GitURL:              repo.GitURL,
		MirrorURL:           repo.MirrorURL,
		SSHURL:              repo.SSHURL,
		Language:            repo.Language,
		Fork:                repo.Fork,
		Size:                repo.Size,
		DeleteBranchOnMerge: repo.DeleteBranchOnMerge,
		Topics:              repo.Topics,
		Archived:            repo.Archived,
		Disabled:            repo.Disabled,
		Private:             repo.Private,
		TeamID:              repo.TeamID,
		Visibility:          repo.Visibility,

		CreatedAt: repo.CreatedAt,
		PushedAt:  repo.PushedAt,
		UpdatedAt: repo.UpdatedAt,
	}
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

func cutString(input string, cut int) string {
	if len(input) > cut {
		return input[:cut] + " ..." // cut long text
	}
	return input
}
