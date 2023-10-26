package codescan

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
)

const (
	tagCode       = "code"
	tagRipository = "repository"
	tagCodeScan   = "codescan"
)

func (s *sqsHandler) putSemgrepFindings(ctx context.Context, projectID uint32, findings []*semgrepFinding) error {
	for _, f := range findings {
		// finding
		buf, err := json.Marshal(f)
		if err != nil {
			return fmt.Errorf("failed to marshal data: project_id=%d, repository=%s, err=%w", projectID, f.Repository, err)
		}
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
			Finding: &finding.FindingForUpsert{
				Description:      fmt.Sprintf("Detect source code finding (%s)", f.CheckID),
				DataSource:       message.CodeScanDataSource,
				DataSourceId:     generateDataSourceIDForSemgrep(f),
				ResourceName:     f.Repository,
				ProjectId:        projectID,
				OriginalScore:    getScoreSemgrep(f.Extra.Severity),
				OriginalMaxScore: 1.0,
				Data:             string(buf),
			},
		})
		if err != nil {
			return err
		}

		// finding-tag
		for _, t := range []string{tagCode, tagRipository, tagCodeScan, f.Repository} {
			err = s.tagFinding(ctx, t, resp.Finding.FindingId, resp.Finding.ProjectId)
			if err != nil {
				return err
			}
		}

		// recommendation
		recommendContent := getSemgrepRecommend(
			f.Repository,
			f.Path,
			f.CheckID,
			f.Extra.Message,
			f.GitHubURL,
			f.Extra.Lines,
		)
		err = s.putRecommend(ctx, resp.Finding.ProjectId, resp.Finding.FindingId, generateDataSourceIDForSemgrep(f), recommendContent)
		if err != nil {
			return err
		}
	}
	return nil
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
