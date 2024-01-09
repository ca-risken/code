package codescan

import (
	"testing"

	"github.com/ca-risken/core/proto/finding"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestGeneratePutFindingRequest(t *testing.T) {
	type args struct {
		projectID uint32
		f         *SemgrepFinding
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
				f: &SemgrepFinding{
					Repository: "org/repo",
					Path:       "path/to/file",
					CheckID:    "check_id",
					Extra: &SemgrepExtra{
						Message: "message",
						Lines:   "lines",
					},
					Start: &SemgrepLine{
						Line:   1,
						Column: 1,
					},
					End: &SemgrepLine{
						Line:   1,
						Column: 1,
					},
				},
			},
			want: &finding.PutFindingRequest{
				ProjectId: 1,
				Finding: &finding.FindingForUpsert{
					Description:      "Detect source code finding (check_id)",
					DataSource:       "code:codescan",
					DataSourceId:     "org/repo/path/to/file/check_id/start-1-1/end-1-1",
					ResourceName:     "org/repo",
					ProjectId:        1,
					OriginalScore:    0,
					OriginalMaxScore: 1.0,
					Data:             `{"repository":"org/repo","check_id":"check_id","path":"path/to/file","start":{"line":1,"col":1},"end":{"line":1,"col":1},"extra":{"lines":"lines","message":"message"}}`,
				},
			},
			wantErr: false,
		},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			got, err := GeneratePutFindingRequest(c.args.projectID, c.args.f)
			if (err != nil) != c.wantErr {
				t.Fatalf("Unexpected error: wantErr=%v, got=%v", c.wantErr, err)
			}
			if diff := cmp.Diff(
				c.want,
				got,
				cmpopts.IgnoreUnexported(
					finding.PutFindingRequest{},
					finding.FindingForUpsert{},
				)); diff != "" {
				t.Fatalf("Unexpected data match: diff=%s", diff)
			}
		})
	}

}
