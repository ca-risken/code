package gitleaks

import (
	"reflect"
	"testing"

	"github.com/ca-risken/core/proto/finding"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-github/v44/github"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestGenerateDataSourceID(t *testing.T) {
	type args struct {
		l LeakFinding
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "OK",
			args: args{
				l: LeakFinding{
					Repo:        "owner/repo_name",
					Commit:      "commit",
					File:        "file",
					StartLine:   1,
					EndLine:     1,
					StartColumn: 1,
				},
			},
			want: "a8666d8dc362b3316a8949c66aa1f838aa7206a00820c0972bd139a73aa4d842",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.l.GenerateDataSourceID()
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Unexpected value, diff=%s", diff)
			}
		})
	}
}

func TestGenerateGitHubURLForGitleaks(t *testing.T) {
	type args struct {
		repositoryURL string
		f             *LeakFinding
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "OK",
			args: args{
				repositoryURL: "https://github.com/org/repo",
				f: &LeakFinding{
					StartLine: 1,
					EndLine:   1,
					Commit:    "commit",
					File:      "file",
				},
			},
			want: "https://github.com/org/repo/blob/commit/file#L1-L1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.f.GenerateGitHubURL(tt.args.repositoryURL)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Unexpected value, diff=%s", diff)
			}
		})
	}
}

func TestGeneratePutFindingRequest(t *testing.T) {
	type args struct {
		projectID uint32
		f         *GitleaksFinding
	}
	tests := []struct {
		name    string
		args    args
		want    *finding.PutFindingRequest
		wantErr bool
	}{
		{
			name: "OK",
			args: args{
				projectID: 1,
				f: &GitleaksFinding{
					RepositoryMetadata: &RepositoryMetadata{
						ID:         github.Int64(1),
						Name:       github.String("repo_name"),
						FullName:   github.String("owner/repo_name"),
						Visibility: github.String("public"),
						Language:   github.String("go"),
					},
					Result: &LeakFinding{
						DataSourceID:    "93527870b4fd88037267c21cdd91173d6961b9e1465d329304fa3955be4f50e9",
						URL:             "html_url/blob/commit/file#L1-L1",
						Repo:            "owner/repo_name",
						RuleDescription: "rule_description",
					},
				},
			},
			want: &finding.PutFindingRequest{
				ProjectId: 1,
				Finding: &finding.FindingForUpsert{
					Description:      "Detected a rule_description secret. (public=true, lang=go)",
					DataSource:       "code:gitleaks",
					DataSourceId:     "93527870b4fd88037267c21cdd91173d6961b9e1465d329304fa3955be4f50e9",
					ResourceName:     "owner/repo_name",
					ProjectId:        1,
					OriginalScore:    1.0,
					OriginalMaxScore: 1.0,
					Data:             `{"repository_metadata":{"id":1,"name":"repo_name","full_name":"owner/repo_name","language":"go","visibility":"public"},"results":{"data_source_id":"93527870b4fd88037267c21cdd91173d6961b9e1465d329304fa3955be4f50e9","repo":"owner/repo_name","ruleDescription":"rule_description","url":"html_url/blob/commit/file#L1-L1"}}`,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GeneratePutFindingRequest(tt.args.projectID, tt.args.f)
			if (err != nil) != tt.wantErr {
				t.Errorf("GeneratePutFindingRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(
				got,
				tt.want,
				cmpopts.IgnoreUnexported(
					finding.PutFindingRequest{},
					finding.FindingForUpsert{},
				)); diff != "" {
				t.Errorf("Unexpected value, diff=%s", diff)
			}
		})
	}
}

func TestGenrateGitleaksFinding(t *testing.T) {
	type args struct {
		repo  *github.Repository
		leaks []report.Finding
	}
	tests := []struct {
		name string
		args args
		want []*GitleaksFinding
	}{
		{
			name: "OK",
			args: args{
				repo: &github.Repository{
					ID:                  github.Int64(1),
					NodeID:              github.String("node_id"),
					Name:                github.String("repo_name"),
					FullName:            github.String("owner/repo_name"),
					Description:         github.String("description"),
					Homepage:            github.String("homepage"),
					HTMLURL:             github.String("html_url"),
					CloneURL:            github.String("clone_url"),
					GitURL:              github.String("git_url"),
					MirrorURL:           github.String("mirror_url"),
					SSHURL:              github.String("ssh_url"),
					Language:            github.String("language"),
					Fork:                github.Bool(false),
					Size:                github.Int(1),
					DeleteBranchOnMerge: github.Bool(false),
					Topics:              []string{"topic1", "topic2"},
					Archived:            github.Bool(false),
					Disabled:            github.Bool(false),
					Private:             github.Bool(false),
					TeamID:              github.Int64(1),
					Visibility:          github.String("public"),
				},
				leaks: []report.Finding{
					{
						StartColumn: 1,
						StartLine:   1,
						EndLine:     1,
						Commit:      "commit",
						File:        "file",
						Secret:      "REDACT",
						Description: "rule_description",
						Message:     "message",
						Author:      "author",
						Email:       "email",
						Date:        "date",
						Tags:        []string{"tag1", "tag2"},
					},
				},
			},
			want: []*GitleaksFinding{
				{
					RepositoryMetadata: &RepositoryMetadata{
						ID:                  github.Int64(1),
						NodeID:              github.String("node_id"),
						Name:                github.String("repo_name"),
						FullName:            github.String("owner/repo_name"),
						Description:         github.String("description"),
						Homepage:            github.String("homepage"),
						CloneURL:            github.String("clone_url"),
						GitURL:              github.String("git_url"),
						MirrorURL:           github.String("mirror_url"),
						SSHURL:              github.String("ssh_url"),
						Language:            github.String("language"),
						Fork:                github.Bool(false),
						Size:                github.Int(1),
						DeleteBranchOnMerge: github.Bool(false),
						Topics:              []string{"topic1", "topic2"},
						Archived:            github.Bool(false),
						Disabled:            github.Bool(false),
						Private:             github.Bool(false),
						TeamID:              github.Int64(1),
						Visibility:          github.String("public"),
					},
					Result: &LeakFinding{
						DataSourceID: "93527870b4fd88037267c21cdd91173d6961b9e1465d329304fa3955be4f50e9",
						URL:          "html_url/blob/commit/file#L1-L1",

						StartColumn:     1,
						StartLine:       1,
						EndLine:         1,
						Commit:          "commit",
						Repo:            "owner/repo_name",
						Secret:          "REDACT",
						RuleDescription: "rule_description",
						Message:         "message",
						Author:          "author",
						Email:           "email",
						File:            "file",
						Date:            "date",
						Tags:            []string{"tag1", "tag2"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenrateGitleaksFinding(tt.args.repo, tt.args.leaks)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Unexpected value, diff=%s", diff)
			}
		})
	}
}

func TestGetRecommend(t *testing.T) {
	type args struct {
		rule        string
		repoName    string
		fileName    string
		visibility  string
		githubURL   string
		author      string
		authorEmail string
	}

	cases := []struct {
		name  string
		input *args
		want  *Recommend
	}{
		{
			name: "OK Blank",
			input: &args{
				rule:        "RULE",
				repoName:    "REPO_NAME",
				fileName:    "FILE_NAME",
				visibility:  "VISIBILITY",
				githubURL:   "https://github.com/ca-risken/",
				author:      "ALICE",
				authorEmail: "alice@example.com",
			},
			want: &Recommend{
				Risk: `RULE
- Secret key has been saved in the FILE_NAME file in the REPO_NAME repository (VISIBILITY repository)
- If a key is leaked, a cyber attack is possible within the scope of the key's authority
- For example, they can break into the cloud platform, destroy critical resources, access or edit with sensitive data, and so on.`,
				Recommendation: `Take the following actions for leaked keys
- Check the GitHub link for the key that has been committed.
	- GitHub URL: https://github.com/ca-risken/
- Check which environments the key has access to and what permissions it has (check with the Author of the commit if possible).
	- Author: ALICE <alice@example.com>
- Make sure you can rotate the key that has leaked.(If it is possible, do it immediately)
- Reduce the number of roles associated with the leaked key or restrict the key's usage conditions
- Next if the key activity can be confirmed from audit logs, etc., we will conduct a damage assessment.`,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetRecommend(c.input.rule, c.input.repoName, c.input.fileName, c.input.visibility, c.input.githubURL, c.input.author, c.input.authorEmail)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data match: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGetGitleaksScore(t *testing.T) {
	type args struct {
		visibility string
	}
	tests := []struct {
		name string
		args args
		want float32
	}{
		{
			name: "OK public",
			args: args{
				visibility: "public",
			},
			want: 1.0,
		},
		{
			name: "OK internal",
			args: args{
				visibility: "internal",
			},
			want: 0.8,
		},
		{
			name: "OK private",
			args: args{
				visibility: "private",
			},
			want: 0.8,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getGitleaksScore(tt.args.visibility); got != tt.want {
				t.Errorf("getGitleaksScore() = %v, want %v", got, tt.want)
			}
		})
	}
}
