package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
)

type vulnerabililityIndex struct {
	packageName string
	vulnID      string
}

func makeFindings(msg *message.CodeQueueMessage, report *trivytypes.Report, repositoryID int64) ([]*finding.FindingBatchForUpsert, error) {
	var findings []*finding.FindingBatchForUpsert
	results := report.Results
	for _, result := range results {
		// ファイル/パッケージ/脆弱性ごとにFindingを生成するためにマッピング
		mapVulnerabilities := make(map[vulnerabililityIndex][]trivytypes.DetectedVulnerability)
		for _, vulnerability := range result.Vulnerabilities {
			vi := vulnerabililityIndex{vulnerability.PkgName, vulnerability.VulnerabilityID}
			mapVulnerabilities[vi] = append(mapVulnerabilities[vi], vulnerability)
		}
		for vi, vuls := range mapVulnerabilities {
			targetInfo := map[string]string{
				"repositoryURL": report.ArtifactName,
				"target":        result.Target,
				"packageName":   vi.packageName,
			}
			data, err := json.Marshal(map[string]interface{}{"target": targetInfo, "vulnerabilities": vuls})
			if err != nil {
				return nil, err
			}
			score, err := getScore(vuls)
			if err != nil {
				return nil, err
			}
			f := finding.FindingForUpsert{
				Description:      getDescription(vi.vulnID, vi.packageName, report.ArtifactName),
				DataSource:       message.DependencyDataSource,
				DataSourceId:     generateDataSourceID(fmt.Sprintf("%s_%s_%s_%s", report.ArtifactName, result.Target, vi.packageName, vi.vulnID)),
				ResourceName:     vi.packageName,
				ProjectId:        msg.ProjectID,
				OriginalScore:    score,
				OriginalMaxScore: 1.0,
				Data:             string(data),
			}
			findings = append(findings, &finding.FindingBatchForUpsert{
				Finding:   &f,
				Recommend: getRecommend(vi.packageName),
				Tag: []*finding.FindingTagForBatch{
					{Tag: tagCode},
					{Tag: tagRepository},
					{Tag: tagDependency},
					// ex) gomod,pip
					{Tag: result.Type},
					{Tag: fmt.Sprintf("repository_id:%v", repositoryID)},
				},
			})
		}

	}
	return findings, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, findings []*finding.FindingBatchForUpsert) error {
	for idx := 0; idx < len(findings); idx = idx + finding.PutFindingBatchMaxLength {
		lastIdx := idx + finding.PutFindingBatchMaxLength
		if lastIdx > len(findings) {
			lastIdx = len(findings)
		}
		req := &finding.PutFindingBatchRequest{ProjectId: projectID, Finding: findings[idx:lastIdx]}
		if _, err := s.findingClient.PutFindingBatch(ctx, req); err != nil {
			return err
		}
	}

	return nil
}

const (
	tagCode       = "code"
	tagRepository = "repository"
	tagDependency = "dependency"
)

func getRecommend(module string) *finding.RecommendForBatch {
	return &finding.RecommendForBatch{
		Type: module,
		Risk: fmt.Sprintf(`One or more vulnerabilities are discovered in %s.
		- Check Finding for more information on the impact of the vulnerability and other details.`, module),
		Recommendation: `Take the following actions for vulnerable package.
		- Check Finding and update the package to the FixedVersion.
		- If the vulnerability has not been fixed, please check References and take interim action.`,
	}
}

func generateDataSourceID(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func getDescription(vulnerabilityID, target, repository string) string {
	return fmt.Sprintf("Vulnerability %s found in %s. Repository: %s", vulnerabilityID, target, repository)
}

func getScore(vulnerabilities []trivytypes.DetectedVulnerability) (float32, error) {
	mapSeverityScore := map[string]float32{
		SEVERITY_CRITICAL: SCORE_CRITICAL,
		SEVERITY_HIGH:     SCORE_HIGH,
		SEVERITY_MEDIUM:   SCORE_MEDIUM,
		SEVERITY_LOW:      SCORE_LOW,
		SEVERITY_UNKNOWN:  SCORE_UNKNOWN,
	}
	score := SCORE_LOW
	// 各パッケージごとに一番Severityの高い脆弱性にスコアを合わせる
	for _, vuls := range vulnerabilities {
		s, ok := mapSeverityScore[vuls.Severity]
		if !ok {
			return 0, fmt.Errorf("unknown severity: %s", vuls.Severity)
		}
		if s > score {
			score = s
		}
	}
	return score, nil
}

const (
	SEVERITY_CRITICAL = "CRITICAL"
	SEVERITY_HIGH     = "HIGH"
	SEVERITY_MEDIUM   = "MEDIUM"
	SEVERITY_LOW      = "LOW"
	SEVERITY_UNKNOWN  = "UNKNOWN"
	SCORE_CRITICAL    = float32(0.6)
	SCORE_HIGH        = float32(0.5)
	SCORE_MEDIUM      = float32(0.3)
	SCORE_LOW         = float32(0.1)
	SCORE_UNKNOWN     = float32(0.1)
)
