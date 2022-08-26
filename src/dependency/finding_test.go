package main

import (
	"reflect"
	"testing"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
)

func TestMakeFinding(t *testing.T) {
	cases := []struct {
		name    string
		msg     *message.CodeQueueMessage
		report  *types.Report
		want    []*finding.FindingBatchForUpsert
		wantErr bool
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
					Tag:       []*finding.FindingTagForBatch{{Tag: tagCode}, {Tag: tagRepository}, {Tag: tagDependency}, {Tag: "module"}},
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
					Tag:       []*finding.FindingTagForBatch{{Tag: tagCode}, {Tag: tagRepository}, {Tag: tagDependency}, {Tag: "module"}},
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
					Tag:       []*finding.FindingTagForBatch{{Tag: tagCode}, {Tag: tagRepository}, {Tag: tagDependency}, {Tag: "module"}},
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
					Tag:       []*finding.FindingTagForBatch{{Tag: tagCode}, {Tag: tagRepository}, {Tag: tagDependency}, {Tag: "module"}},
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
			got, err := makeFindings(c.msg, c.report)
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
			want: 0.9,
		},
		{
			name: "OK High",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "HIGH"}},
			},
			want: 0.8,
		},
		{
			name: "OK Medium",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "MEDIUM"}},
			},
			want: 0.6,
		},
		{
			name: "OK Low",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "LOW"}},
			},
			want: 0.3,
		},
		{
			name: "OK Unknown",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "UNKNOWN"}},
			},
			want: 0.6,
		},
		{
			name: "OK Multiple",
			vulnerabilities: []types.DetectedVulnerability{
				{Vulnerability: dbtypes.Vulnerability{Severity: "LOW"}},
				{Vulnerability: dbtypes.Vulnerability{Severity: "MEDIUM"}},
				{Vulnerability: dbtypes.Vulnerability{Severity: "HIGH"}},
				{Vulnerability: dbtypes.Vulnerability{Severity: "CRITICAL"}},
			},
			want: 0.9,
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
			got, err := getScore(c.vulnerabilities)
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected not matching: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
