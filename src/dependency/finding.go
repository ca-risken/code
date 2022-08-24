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

func makeFindings(msg *message.CodeQueueMessage, report *trivytypes.Report) ([]*finding.FindingBatchForUpsert, error) {
	var findings []*finding.FindingBatchForUpsert
	mapVulnerabilities := make(map[string][]trivytypes.DetectedVulnerability)
	results := report.Results
	for _, result := range results {
		// ファイルとパッケージごとにFindingを生成するためにマッピング
		for _, vulnerability := range result.Vulnerabilities {
			mapVulnerabilities[vulnerability.PkgName] = append(mapVulnerabilities[vulnerability.PkgName], vulnerability)
		}
		for pkg, vuls := range mapVulnerabilities {
			targetInfo := map[string]string{
				"repositoryURL": report.ArtifactName,
				"target":        result.Target,
				"packageName":   pkg,
			}
			data, err := json.Marshal(map[string]interface{}{"target": targetInfo, "vulnerabilities": vuls})
			if err != nil {
				return nil, err
			}
			f := finding.FindingForUpsert{
				Description:      getDescription(pkg, report.ArtifactName),
				DataSource:       message.DependencyDataSource,
				DataSourceId:     generateDataSourceID(fmt.Sprintf("%s_%s_%s", report.ArtifactName, result.Target, pkg)),
				ResourceName:     pkg,
				ProjectId:        msg.ProjectID,
				OriginalScore:    getScore(vuls),
				OriginalMaxScore: 1.0,
				Data:             string(data),
			}
			findings = append(findings, &finding.FindingBatchForUpsert{
				Finding:   &f,
				Recommend: getRecommend(pkg),
				Tag: []*finding.FindingTagForBatch{
					{Tag: tagCode},
					{Tag: tagRepository},
					{Tag: tagDependency},
					// ex) gomod,pip
					{Tag: result.Type},
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

func getDescription(target, repository string) string {
	return fmt.Sprintf("One or more vulnerabilities are discovered in %s. Repository: %s", target, repository)
}

func getScore(vulnerabilities []trivytypes.DetectedVulnerability) float32 {
	severity := "UNKNOWN"
	// 各パッケージごとに一番Severityの高い脆弱性にスコアを合わせる
	for _, vuls := range vulnerabilities {
		switch vuls.Severity {
		case "CRITICAL":
			severity = "CRITICAL"
		case "HIGH":
			if severity != "CRITICAL" {
				severity = "HIGH"
			}
		case "MEDIUM":
			if severity != "CRITICAL" && severity != "HIGH" {
				severity = "MEDIUM"
			}
		case "LOW":
			if severity != "UNKNOWN" {
				severity = "LOW"
			}
		}
	}
	switch severity {
	case "CRITICAL":
		return SCORE_CRITICAL
	case "HIGH":
		return SCORE_HIGH
	case "MEDIUM":
		return SCORE_MEDIUM
	case "LOW":
		return SCORE_LOW
	default:
		return SCORE_DEFAULT
	}
}

const (
	SCORE_CRITICAL = 0.9
	SCORE_HIGH     = 0.8
	SCORE_MEDIUM   = 0.6
	SCORE_LOW      = 0.3
	SCORE_DEFAULT  = 0.6
)
