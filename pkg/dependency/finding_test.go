package dependency

import (
	"context"
	"errors"
	"reflect"
	"testing"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/core/proto/finding"
	findingmock "github.com/ca-risken/core/proto/finding/mocks"
	"github.com/ca-risken/datasource-api/pkg/message"
)

func TestPutResource(t *testing.T) {
	cases := []struct {
		name                 string
		projectID            uint32
		resourceName         string
		mockPutResource      *finding.PutResourceResponse
		mockPutResourceError error
		tags                 []string
		mockTagResourceError error
		wantErr              bool
	}{
		{
			name:         "OK",
			projectID:    1,
			resourceName: "resource_name",
			mockPutResource: &finding.PutResourceResponse{
				Resource: &finding.Resource{
					ResourceId:   1,
					ResourceName: "resource_name",
					ProjectId:    1,
				},
			},
			mockPutResourceError: nil,
			tags:                 []string{"code", "repository"},
			mockTagResourceError: nil,
			wantErr:              false,
		},
		{
			name:                 "NG PutResource Error",
			projectID:            1,
			resourceName:         "resource_name",
			mockPutResource:      nil,
			mockPutResourceError: errors.New("something error"),
			wantErr:              true,
		},
		{
			name:         "NG TagResource Error",
			projectID:    1,
			resourceName: "resource_name",
			mockPutResource: &finding.PutResourceResponse{
				Resource: &finding.Resource{
					ResourceId:   1,
					ResourceName: "resource_name",
					ProjectId:    1,
				},
			},
			mockPutResourceError: nil,
			tags:                 []string{"code"},
			mockTagResourceError: errors.New("something error"),
			wantErr:              true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			mockFinding := findingmock.FindingServiceClient{}
			mockFinding.On("PutResource", ctx, &finding.PutResourceRequest{
				ProjectId: c.projectID,
				Resource: &finding.ResourceForUpsert{
					ResourceName: c.resourceName,
					ProjectId:    c.projectID,
				},
			}).Return(c.mockPutResource, c.mockPutResourceError)
			for _, t := range c.tags {
				mockFinding.On("TagResource", ctx, &finding.TagResourceRequest{
					ProjectId: c.projectID,
					Tag: &finding.ResourceTagForUpsert{
						ResourceId: c.mockPutResource.Resource.ResourceId,
						ProjectId:  c.projectID,
						Tag:        t,
					},
				}).Return(&finding.TagResourceResponse{}, c.mockTagResourceError)
			}
			s := sqsHandler{
				findingClient: &mockFinding,
				logger:        logging.NewLogger(),
			}
			err := s.putResource(ctx, c.projectID, c.resourceName)
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}
		})
	}
}

func TestMakeFinding(t *testing.T) {
	cases := []struct {
		name         string
		msg          *message.CodeQueueMessage
		report       *types.Report
		repositoryID int64
		want         []*finding.FindingBatchForUpsert
		wantErr      bool
	}{
		{
			name: "OK",
			msg: &message.CodeQueueMessage{
				GitHubSettingID: 1001,
				ProjectID:       1001,
				ScanOnly:        false,
			},
			report: &types.Report{
				ArtifactName: "artifact_name",
				Results: []types.Result{
					{
						Type:   "module",
						Target: "target",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgName: "pkg",
								Vulnerability: dbtypes.Vulnerability{
									Severity: "HIGH",
								},
							},
						},
					},
				},
			},
			repositoryID: 1,
			want: []*finding.FindingBatchForUpsert{
				{
					Finding: &finding.FindingForUpsert{
						Description:      "One or more vulnerabilities are discovered in pkg. Repository: artifact_name",
						DataSource:       "code:dependency",
						DataSourceId:     generateDataSourceID("artifact_name_target_pkg"),
						ResourceName:     "pkg",
						ProjectId:        1001,
						OriginalScore:    0.8,
						OriginalMaxScore: 1.0,
						Data:             "{\"target\":{\"packageName\":\"pkg\",\"repositoryURL\":\"artifact_name\",\"target\":\"target\"},\"vulnerabilities\":[{\"PkgName\":\"pkg\",\"Layer\":{},\"Severity\":\"HIGH\"}]}",
					},
					Recommend: getRecommend("pkg"),
					Tag:       []*finding.FindingTagForBatch{{Tag: tagCode}, {Tag: tagDependency}, {Tag: "module"}, {Tag: "repository_id:1"}},
				},
			},
		},
		{
			name: "OK multiple module",
			msg: &message.CodeQueueMessage{
				GitHubSettingID: 1001,
				ProjectID:       1001,
				ScanOnly:        false,
			},
			report: &types.Report{
				ArtifactName: "artifact_name",
				Results: []types.Result{
					{
						Type:   "module",
						Target: "target",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgName: "pkg",
								Vulnerability: dbtypes.Vulnerability{
									Severity: "LOW",
								},
							},
							{
								PkgName: "pkg2",
								Vulnerability: dbtypes.Vulnerability{
									Severity: "MEDIUM",
								},
							},
						},
					},
				},
			},
			repositoryID: 1,
			want: []*finding.FindingBatchForUpsert{
				{
					Finding: &finding.FindingForUpsert{
						Description:      "One or more vulnerabilities are discovered in pkg. Repository: artifact_name",
						DataSource:       "code:dependency",
						DataSourceId:     generateDataSourceID("artifact_name_target_pkg"),
						ResourceName:     "pkg",
						ProjectId:        1001,
						OriginalScore:    0.3,
						OriginalMaxScore: 1.0,
						Data:             "{\"target\":{\"packageName\":\"pkg\",\"repositoryURL\":\"artifact_name\",\"target\":\"target\"},\"vulnerabilities\":[{\"PkgName\":\"pkg\",\"Layer\":{},\"Severity\":\"LOW\"}]}",
					},
					Recommend: getRecommend("pkg"),
					Tag:       []*finding.FindingTagForBatch{{Tag: tagCode}, {Tag: tagDependency}, {Tag: "module"}, {Tag: "repository_id:1"}},
				},
				{
					Finding: &finding.FindingForUpsert{
						Description:      "One or more vulnerabilities are discovered in pkg2. Repository: artifact_name",
						DataSource:       "code:dependency",
						DataSourceId:     generateDataSourceID("artifact_name_target_pkg2"),
						ResourceName:     "pkg2",
						ProjectId:        1001,
						OriginalScore:    0.6,
						OriginalMaxScore: 1.0,
						Data:             "{\"target\":{\"packageName\":\"pkg2\",\"repositoryURL\":\"artifact_name\",\"target\":\"target\"},\"vulnerabilities\":[{\"PkgName\":\"pkg2\",\"Layer\":{},\"Severity\":\"MEDIUM\"}]}",
					},
					Recommend: getRecommend("pkg2"),
					Tag:       []*finding.FindingTagForBatch{{Tag: tagCode}, {Tag: tagDependency}, {Tag: "module"}, {Tag: "repository_id:1"}},
				},
			},
		},
		{
			name: "OK multiple vulnerability",
			msg: &message.CodeQueueMessage{
				GitHubSettingID: 1001,
				ProjectID:       1001,
				ScanOnly:        false,
			},
			report: &types.Report{
				ArtifactName: "artifact_name",
				Results: []types.Result{
					{
						Type:   "module",
						Target: "target",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgName: "pkg",
								Vulnerability: dbtypes.Vulnerability{
									Severity: "LOW",
								},
							},
							{
								PkgName: "pkg",
								Vulnerability: dbtypes.Vulnerability{
									Severity: "MEDIUM",
								},
							},
						},
					},
				},
			},
			repositoryID: 1,
			want: []*finding.FindingBatchForUpsert{
				{
					Finding: &finding.FindingForUpsert{
						Description:      "One or more vulnerabilities are discovered in pkg. Repository: artifact_name",
						DataSource:       "code:dependency",
						DataSourceId:     generateDataSourceID("artifact_name_target_pkg"),
						ResourceName:     "pkg",
						ProjectId:        1001,
						OriginalScore:    0.6,
						OriginalMaxScore: 1.0,
						Data:             "{\"target\":{\"packageName\":\"pkg\",\"repositoryURL\":\"artifact_name\",\"target\":\"target\"},\"vulnerabilities\":[{\"PkgName\":\"pkg\",\"Layer\":{},\"Severity\":\"LOW\"},{\"PkgName\":\"pkg\",\"Layer\":{},\"Severity\":\"MEDIUM\"}]}",
					},
					Recommend: getRecommend("pkg"),
					Tag:       []*finding.FindingTagForBatch{{Tag: tagCode}, {Tag: tagDependency}, {Tag: "module"}, {Tag: "repository_id:1"}},
				},
			},
		},
		{
			name: "OK empty",
			msg: &message.CodeQueueMessage{
				GitHubSettingID: 1003,
				ProjectID:       1001,
				ScanOnly:        false,
			},
			report: &types.Report{},
			want:   nil,
		},
		{
			name: "NG undefined score",
			msg: &message.CodeQueueMessage{
				GitHubSettingID: 1001,
				ProjectID:       1001,
				ScanOnly:        false,
			},
			report: &types.Report{
				ArtifactName: "artifact_name",
				Results: []types.Result{
					{
						Type:   "module",
						Target: "target",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								PkgName: "pkg",
								Vulnerability: dbtypes.Vulnerability{
									Severity: "UNDEFINED",
								},
							},
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			s := sqsHandler{}
			got, err := s.makeFindings(ctx, c.msg, c.report, c.repositoryID)
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}
			if len(c.want) != len(got) {
				t.Fatalf("Unexpected not matching length: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetScore(t *testing.T) {
	cases := []struct {
		name            string
		vulnerabilities []types.DetectedVulnerability
		want            float32
		wantErr         bool
	}{
		{
			name: "OK Critical",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "CRITICAL"}},
			},
			want: 0.6,
		},
		{
			name: "OK High",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "HIGH"}},
			},
			want: 0.5,
		},
		{
			name: "OK Medium",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "MEDIUM"}},
			},
			want: 0.3,
		},
		{
			name: "OK Low",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "LOW"}},
			},
			want: 0.1,
		},
		{
			name: "OK Unknown",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "UNKNOWN"}},
			},
			want: 0.1,
		},
		{
			name: "OK Multiple",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "LOW"}},
				{Vulnerability: dbtypes.Vulnerability{Severity: "MEDIUM"}},
				{Vulnerability: dbtypes.Vulnerability{Severity: "HIGH"}},
				{Vulnerability: dbtypes.Vulnerability{Severity: "CRITICAL"}},
			},
			want: 0.6,
		},
		{
			name: "NG Undefined Severity",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "UNDEFINED"}},
			},
			want:    0.0,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			highestVuln, err := getHighScoreVuln(c.vulnerabilities)
			if c.wantErr && err == nil {
				t.Fatal("[getHighScoreVuln] Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("[getHighScoreVuln] Unexpected error occured, err=%+v", err)
			}
			if highestVuln == nil {
				return
			}

			got, err := getScore(highestVuln)
			if c.wantErr && err == nil {
				t.Fatal("[getScore] Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("[getScore] Unexpected error occured, err=%+v", err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("[getScore] Unexpected not matching: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
