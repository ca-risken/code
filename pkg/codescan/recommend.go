package codescan

import (
	"context"
	"fmt"

	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
)

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getSemgrepRecommend(repoName, fileName, rule, semgrepMessage, githubURL, line string) *recommend {
	return &recommend{
		Risk: fmt.Sprintf(`A problem code detected in %s file in %s repository.
- DetectedRule: %s
- %s`,
			fileName,
			repoName,
			rule,
			semgrepMessage,
		),
		Recommendation: fmt.Sprintf(`Take the following actions
- Check the source code.
	- GitHub URL: %s
	- Specific code line:
------------------------------
%s
------------------------------
- Fix the source code with the following message.
	- %s`,
			githubURL,
			line,
			semgrepMessage,
		),
	}
}

func (s *sqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, recommendType string, r *recommend) error {
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     message.CodeScanDataSource,
		Type:           recommendType,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		return fmt.Errorf("failed to PutRecommend, finding_id=%d, type=%s, error=%w", findingID, recommendType, err)
	}
	return nil
}
