package code

import (
	"testing"
	"time"
)

const (
	stringLength65           = "12345678901234567890123456789012345678901234567890123456789012345"
	stringLength129          = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789=12345678901234567890123456789"
	stringLength256          = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789=123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789=12345678901234567890123456789012345678901234567890123456"
	unixtime19691231T235959  = -1
	unixtime100000101T000000 = 253402268400
)

func TestValidate_ListDataSourceRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *ListDataSourceRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &ListDataSourceRequest{CodeDataSourceId: 1, Name: "name"},
		},
		{
			name:  "OK empty",
			input: &ListDataSourceRequest{},
		},
		{
			name:    "NG length(name)",
			input:   &ListDataSourceRequest{CodeDataSourceId: 1, Name: stringLength65},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_ListGitleaksRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *ListGitleaksRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &ListGitleaksRequest{ProjectId: 1, CodeDataSourceId: 1, GitleaksId: 1},
		},
		{
			name:    "NG Required(project_id)",
			input:   &ListGitleaksRequest{CodeDataSourceId: 1, GitleaksId: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_PutGitleaksRequest(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		input   *PutGitleaksRequest
		wantErr bool
	}{
		{
			name: "OK",
			input: &PutGitleaksRequest{ProjectId: 1, Gitleaks: &GitleaksForUpsert{
				ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "", Status: Status_OK, ScanAt: now.Unix(),
			}},
		},
		{
			name:    "NG No gitleaks",
			input:   &PutGitleaksRequest{ProjectId: 1},
			wantErr: true,
		},
		{
			name: "NG Invalid project_id",
			input: &PutGitleaksRequest{ProjectId: 999, Gitleaks: &GitleaksForUpsert{
				ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "", Status: Status_OK, ScanAt: now.Unix(),
			}},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_DeleteGitleaksRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *DeleteGitleaksRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &DeleteGitleaksRequest{ProjectId: 1, GitleaksId: 1},
		},
		{
			name:    "NG Required(project_id)",
			input:   &DeleteGitleaksRequest{GitleaksId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(gitleaks_id)",
			input:   &DeleteGitleaksRequest{ProjectId: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_InvokeScanGitleaksRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *InvokeScanGitleaksRequest
		wantErr bool
	}{
		{
			name:  "OK",
			input: &InvokeScanGitleaksRequest{ProjectId: 1, GitleaksId: 1},
		},
		{
			name:    "NG Required(project_id)",
			input:   &InvokeScanGitleaksRequest{GitleaksId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(gitleaks_id)",
			input:   &InvokeScanGitleaksRequest{ProjectId: 1},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestValidate_GitleaksForUpsert(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		input   *GitleaksForUpsert
		wantErr bool
	}{
		{
			name: "OK",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "some-repo", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, StatusDetail: "detail", ScanAt: now.Unix(),
			},
		},
		{
			name: "OK minimize",
			input: &GitleaksForUpsert{
				ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", GithubUser: "user", PersonalAccessToken: "xxx",
			},
		},
		{
			name: "NG Length(name)",
			input: &GitleaksForUpsert{
				Name: stringLength65, ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "some-repo", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Required(project_id)",
			input: &GitleaksForUpsert{
				Name: "name", Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "some-repo", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Required(targetResource)",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "", RepositoryPattern: "some-repo", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Length(targetResource)",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: stringLength129, RepositoryPattern: "some-repo", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Length(RepositoryPattern)",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: stringLength129, GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Uncompilable(RepositoryPattern)",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "*xxx", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Length(github_user)",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "some-repo", GithubUser: stringLength65, PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Length(personal_access_token)",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "some-repo", GithubUser: "user", PersonalAccessToken: stringLength256, GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Length(status_detail)",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "some-repo", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, StatusDetail: stringLength256, ScanAt: now.Unix(),
			},
			wantErr: true,
		},
		{
			name: "NG Min(scan_at)",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "some-repo", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: unixtime19691231T235959,
			},
			wantErr: true,
		},
		{
			name: "NG Max(scan_at)",
			input: &GitleaksForUpsert{
				Name: "name", ProjectId: 1, Type: Type_ENTERPRISE, TargetResource: "target", RepositoryPattern: "some-repo", GithubUser: "user", PersonalAccessToken: "xxx", GitleaksConfig: "xxxx", Status: Status_OK, ScanAt: unixtime100000101T000000,
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}
