package gitleaks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/google/go-github/v44/github"
	"github.com/zricethezav/gitleaks/v8/report"
)

type GitleaksFinding struct {
	*RepositoryMetadata `json:"repository_metadata,omitempty"`
	Result              *LeakFinding `json:"results,omitempty"`
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
}

type LeakFinding struct {
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

func (l *LeakFinding) GenerateDataSourceID() string {
	hash := sha256.Sum256([]byte(l.Repo + l.Commit + l.Secret + l.File + fmt.Sprint(l.StartLine) + fmt.Sprint(l.EndLine) + fmt.Sprint(l.StartColumn)))
	return hex.EncodeToString(hash[:])
}

func (l *LeakFinding) GenerateGitHubURL(repositoryURL string) string {
	url := fmt.Sprintf("%s/blob/%s/%s#L%d-L%d", repositoryURL, l.Commit, l.File, l.StartLine, l.EndLine)
	return url
}

func GeneratePutFindingRequest(projectID uint32, f *GitleaksFinding) (*finding.PutFindingRequest, error) {
	buf, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user data: project_id=%d, repository=%s, err=%w", projectID, toString(f.FullName), err)
	}
	return &finding.PutFindingRequest{
		ProjectId: projectID,
		Finding: &finding.FindingForUpsert{
			Description: fmt.Sprintf(
				"Detected a %s secret. (public=%t, lang=%s)",
				f.Result.RuleDescription,
				toString(f.Visibility) == "public",
				toString(f.Language),
			),
			DataSource:       message.GitleaksDataSource,
			DataSourceId:     f.Result.DataSourceID,
			ResourceName:     toString(f.FullName),
			ProjectId:        projectID,
			OriginalScore:    defaultGitleaksScore,
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	}, nil
}

func GenrateGitleaksFinding(repo *github.Repository, leaks []report.Finding) []*GitleaksFinding {
	m := &RepositoryMetadata{
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
	var findings []*GitleaksFinding
	for _, leak := range leaks {
		l := &LeakFinding{
			StartColumn:     leak.StartColumn,
			StartLine:       leak.StartLine,
			EndLine:         leak.EndLine,
			Commit:          leak.Commit,
			Secret:          leak.Secret,
			Repo:            *m.FullName,
			RuleDescription: leak.Description,
			Message:         leak.Message,
			Author:          leak.Author,
			Email:           leak.Email,
			File:            leak.File,
			Date:            leak.Date,
			Tags:            leak.Tags,
		}
		l.DataSourceID = l.GenerateDataSourceID()
		l.URL = l.GenerateGitHubURL(*repo.HTMLURL)
		findings = append(findings, &GitleaksFinding{
			RepositoryMetadata: m,
			Result:             l,
		})
	}
	return findings
}

type Recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func GetRecommend(rule, repoName, fileName, visibility, githubURL, author, authorEmail string) *Recommend {
	return &Recommend{
		Risk: fmt.Sprintf(`%s
- Secret key has been saved in the file in the repository (%s repository)
- If a key is leaked, a cyber attack is possible within the scope of the key's authority
- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
			rule,
			visibility,
		),
		Recommendation: fmt.Sprintf(`Take the following actions for leaked keys
- Check the GitHub link for the key that has been committed.
	- GitHub URL: %s
- Check which environments the key has access to and what permissions it has (check with the Author of the commit if possible).
	- Author: %s <%s>
- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
- Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
			githubURL,
			author,
			authorEmail,
		),
	}
}

func toString(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}
