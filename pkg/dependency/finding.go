package dependency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	triage "github.com/ca-risken/core/pkg/server/finding"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	vulnmodel "github.com/ca-risken/vulnerability/pkg/model"
	vulnsdk "github.com/ca-risken/vulnerability/pkg/sdk"
)

type vulnerabililityIndex struct {
	packageName string
	vulnID      string
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

type TargetInfo struct {
	RepositoryURL   string `json:"repositoryURL"`
	Target          string `json:"target"`
	PackageName     string `json:"packageName"`
	VulnerabilityID string `json:"vulnerabilityID"`
}

type VulnFinding struct {
	Target        TargetInfo                       `json:"target"`
	Vulnerability trivytypes.DetectedVulnerability `json:"vulnerability,omitempty"`
	CVEDetail     *vulnmodel.Vulnerability         `json:"cve_detail,omitempty"`
	RiskenTriage  *triage.RiskenTriage             `json:"risken_triage,omitempty"`
}

func (s *sqsHandler) makeFindings(ctx context.Context, msg *message.CodeQueueMessage, report *trivytypes.Report, repositoryID int64) ([]*finding.FindingBatchForUpsert, error) {
	var findings []*finding.FindingBatchForUpsert
	results := report.Results
	for _, result := range results {
		// ファイル/パッケージ/脆弱性ごとにFindingを生成
		mapVulnerability := make(map[vulnerabililityIndex]trivytypes.DetectedVulnerability)
		for _, vulnerability := range result.Vulnerabilities {
			vi := vulnerabililityIndex{vulnerability.PkgName, vulnerability.VulnerabilityID}
			mapVulnerability[vi] = vulnerability
		}
		for vi, vul := range mapVulnerability {
			targetInfo := TargetInfo{
				RepositoryURL:   report.ArtifactName,
				Target:          result.Target,
				PackageName:     vi.packageName,
				VulnerabilityID: vi.vulnID,
			}
			vulnDetail, err := s.getVulnerability(ctx, vi.vulnID)
			if err != nil {
				return nil, err
			}
			vulnFinding := VulnFinding{
				Target:        targetInfo,
				Vulnerability: vul,
				CVEDetail:     vulnDetail,
				RiskenTriage:  vulnsdk.EvaluateVulnerability(vulnDetail),
			}
			data, err := json.Marshal(vulnFinding)
			if err != nil {
				return nil, err
			}
			canTriage := vulnFinding.RiskenTriage != nil
			score, err := getScore(&vul, canTriage)
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
					{Tag: tagDependency},
					{Tag: result.Type}, // ex) gomod,pip
					{Tag: vi.vulnID},   // ex) CVE-2025-12345
					{Tag: fmt.Sprintf("repository_id:%d", repositoryID)},
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
	tagRipository = "repository"
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

const (
	SEVERITY_CRITICAL = "CRITICAL"
	SEVERITY_HIGH     = "HIGH"
	SEVERITY_MEDIUM   = "MEDIUM"
	SEVERITY_LOW      = "LOW"
	SEVERITY_UNKNOWN  = "UNKNOWN"

	// Default Score
	SCORE_CRITICAL = float32(0.6)
	SCORE_HIGH     = float32(0.5)
	SCORE_MEDIUM   = float32(0.3)
	SCORE_LOW      = float32(0.1)
	SCORE_UNKNOWN  = float32(0.1)

	// CVE Score
	SCORE_CVE_CRITICAL = float32(0.8)
	SCORE_CVE_HIGH     = float32(0.6)
	SCORE_CVE_MEDIUM   = float32(0.4)
	SCORE_CVE_LOW      = float32(0.1)
	SCORE_CVE_UNKNOWN  = float32(0.1)
)

// Severity Score
var mapSeverityScore = map[string]float32{
	SEVERITY_CRITICAL: SCORE_CRITICAL,
	SEVERITY_HIGH:     SCORE_HIGH,
	SEVERITY_MEDIUM:   SCORE_MEDIUM,
	SEVERITY_LOW:      SCORE_LOW,
	SEVERITY_UNKNOWN:  SCORE_UNKNOWN,
}

// Triageable Severity Score
// Vulnerabilities that can be automatically triaged (e.g. CVE) have higher scores
// because they contain more information and can be processed systematically
var mapTriageableScore = map[string]float32{
	SEVERITY_CRITICAL: SCORE_CVE_CRITICAL,
	SEVERITY_HIGH:     SCORE_CVE_HIGH,
	SEVERITY_MEDIUM:   SCORE_CVE_MEDIUM,
	SEVERITY_LOW:      SCORE_CVE_LOW,
	SEVERITY_UNKNOWN:  SCORE_CVE_UNKNOWN,
}

func getScore(vuln *trivytypes.DetectedVulnerability, canTriage bool) (float32, error) {
	if vuln == nil {
		return SCORE_LOW, nil
	}
	if canTriage {
		return getTriageableScore(vuln)
	} else {
		return getDefaultScore(vuln)
	}
}

func getTriageableScore(vuln *trivytypes.DetectedVulnerability) (float32, error) {
	score, ok := mapTriageableScore[vuln.Severity]
	if !ok {
		return 0, fmt.Errorf("unknown severity: %s", vuln.Severity)
	}
	return score, nil
}

func getDefaultScore(vuln *trivytypes.DetectedVulnerability) (float32, error) {
	score, ok := mapSeverityScore[vuln.Severity]
	if !ok {
		return 0, fmt.Errorf("unknown severity: %s", vuln.Severity)
	}
	return score, nil
}
