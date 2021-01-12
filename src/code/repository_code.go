package main

import (
	"fmt"
	"time"

	"github.com/CyberAgent/mimosa-code/pkg/common"
	"github.com/CyberAgent/mimosa-code/proto/code"
	_ "github.com/go-sql-driver/mysql"
	"github.com/vikyd/zero"
)

func (c *codeRepository) ListDataSource(codeDataSourceID uint32, name string) (*[]common.CodeDataSource, error) {
	query := `select * from code_data_source where 1=1`
	var params []interface{}
	if !zero.IsZeroVal(codeDataSourceID) {
		query += " and code_data_source_id = ?"
		params = append(params, codeDataSourceID)
	}
	if !zero.IsZeroVal(name) {
		query += " and name = ?"
		params = append(params, name)
	}
	data := []common.CodeDataSource{}
	if err := c.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *codeRepository) ListGitleaks(projectID, codeDataSourceID, gitleaksID uint32) (*[]common.CodeGitleaks, error) {
	query := `select * from code_gitleaks where 1=1`
	var params []interface{}
	if !zero.IsZeroVal(projectID) {
		query += " and project_id = ?"
		params = append(params, projectID)
	}
	if !zero.IsZeroVal(codeDataSourceID) {
		query += " and code_data_source_id = ?"
		params = append(params, codeDataSourceID)
	}
	if !zero.IsZeroVal(gitleaksID) {
		query += " and gitleaks_id = ?"
		params = append(params, gitleaksID)
	}
	data := []common.CodeGitleaks{}
	if err := c.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *codeRepository) UpsertGitleaks(data *code.GitleaksForUpsert) (*common.CodeGitleaks, error) {
	if data.PersonalAccessToken != "" {
		return c.UpsertGitleaksWithToken(data)
	}
	return c.UpsertGitleaksWithoutToken(data)
}

const insertUpsertGitleaksWithToken = `
INSERT INTO code_gitleaks (
  gitleaks_id,
  code_data_source_id,
  name,
  project_id,
  type,
  target_resource,
  repository_pattern,
  github_user,
  personal_access_token,
  scan_public,
  scan_internal,
  scan_private,
  gitleaks_config,
  status,
  status_detail,
  scan_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
	code_data_source_id=VALUES(code_data_source_id),
	name=VALUES(name),
	project_id=VALUES(project_id),
	type=VALUES(type),
	target_resource=VALUES(target_resource),
	repository_pattern=VALUES(repository_pattern),
	github_user=VALUES(github_user),
	personal_access_token=VALUES(personal_access_token),
	scan_public=VALUES(scan_public),
	scan_internal=VALUES(scan_internal),
	scan_private=VALUES(scan_private),
	gitleaks_config=VALUES(gitleaks_config),
	status=VALUES(status),
	status_detail=VALUES(status_detail),
	scan_at=VALUES(scan_at)
`

func (c *codeRepository) UpsertGitleaksWithToken(data *code.GitleaksForUpsert) (*common.CodeGitleaks, error) {
	if err := c.MasterDB.Exec(insertUpsertGitleaksWithToken,
		data.GitleaksId,
		data.CodeDataSourceId,
		convertZeroValueToNull(data.Name),
		data.ProjectId,
		data.Type.String(),
		data.TargetResource,
		convertZeroValueToNull(data.RepositoryPattern),
		convertZeroValueToNull(data.GithubUser),
		convertZeroValueToNull(data.PersonalAccessToken),
		fmt.Sprintf("%t", data.ScanPublic),
		fmt.Sprintf("%t", data.ScanInternal),
		fmt.Sprintf("%t", data.ScanPrivate),
		convertZeroValueToNull(data.GitleaksConfig),
		data.Status.String(),
		convertZeroValueToNull(data.StatusDetail),
		time.Unix(data.ScanAt, 0)).Error; err != nil {
		return nil, err
	}
	return c.GetGitleaksByUniqueIndex(data.ProjectId, data.CodeDataSourceId, data.Name)
}

const insertUpsertGitleaksWithoutToken = `
INSERT INTO code_gitleaks (
  gitleaks_id,
  code_data_source_id,
  name,
  project_id,
  type,
  target_resource,
  repository_pattern,
  github_user,
  scan_public,
  scan_internal,
  scan_private,
  gitleaks_config,
  status,
  status_detail,
  scan_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
	code_data_source_id=VALUES(code_data_source_id),
	name=VALUES(name),
	project_id=VALUES(project_id),
	type=VALUES(type),
	target_resource=VALUES(target_resource),
	repository_pattern=VALUES(repository_pattern),
	github_user=VALUES(github_user),
	scan_public=VALUES(scan_public),
	scan_internal=VALUES(scan_internal),
	scan_private=VALUES(scan_private),
	gitleaks_config=VALUES(gitleaks_config),
	status=VALUES(status),
	status_detail=VALUES(status_detail),
	scan_at=VALUES(scan_at)
`

func (c *codeRepository) UpsertGitleaksWithoutToken(data *code.GitleaksForUpsert) (*common.CodeGitleaks, error) {
	if err := c.MasterDB.Exec(insertUpsertGitleaksWithoutToken,
		data.GitleaksId,
		data.CodeDataSourceId,
		convertZeroValueToNull(data.Name),
		data.ProjectId,
		data.Type.String(),
		data.TargetResource,
		convertZeroValueToNull(data.RepositoryPattern),
		convertZeroValueToNull(data.GithubUser),
		fmt.Sprintf("%t", data.ScanPublic),
		fmt.Sprintf("%t", data.ScanInternal),
		fmt.Sprintf("%t", data.ScanPrivate),
		convertZeroValueToNull(data.GitleaksConfig),
		data.Status.String(),
		convertZeroValueToNull(data.StatusDetail),
		time.Unix(data.ScanAt, 0)).Error; err != nil {
		return nil, err
	}
	return c.GetGitleaksByUniqueIndex(data.ProjectId, data.CodeDataSourceId, data.Name)
}

const deleteGitleaks = `delete from code_gitleaks where project_id=? and gitleaks_id=?`

func (c *codeRepository) DeleteGitleaks(projectID, gitleaksID uint32) error {
	if err := c.MasterDB.Exec(deleteGitleaks, projectID, gitleaksID).Error; err != nil {
		return err
	}
	return nil
}

const selectGetCodeGitleaks = `select * from code_gitleaks where project_id=? and gitleaks_id=?`

func (c *codeRepository) GetGitleaks(projectID, gitleaksID uint32) (*common.CodeGitleaks, error) {
	data := common.CodeGitleaks{}
	if err := c.SlaveDB.Raw(selectGetCodeGitleaks, projectID, gitleaksID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const selectGetCodeGitleaksByUniqueIndex = `select * from code_gitleaks where project_id=? and code_data_source_id=? and name=?`

func (c *codeRepository) GetGitleaksByUniqueIndex(projectID, codeDataSourceID uint32, name string) (*common.CodeGitleaks, error) {
	data := common.CodeGitleaks{}
	if err := c.MasterDB.Raw(selectGetCodeGitleaksByUniqueIndex, projectID, codeDataSourceID, name).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *codeRepository) ListEnterpriseOrg(projectID, gitleaksID uint32) (*[]common.CodeEnterpriseOrg, error) {
	query := `select * from code_enterprise_org where 1=1`
	var params []interface{}
	if !zero.IsZeroVal(projectID) {
		query += " and project_id=?"
		params = append(params, projectID)
	}
	if !zero.IsZeroVal(gitleaksID) {
		query += " and gitleaks_id=?"
		params = append(params, gitleaksID)
	}
	data := []common.CodeEnterpriseOrg{}
	if err := c.MasterDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *codeRepository) UpsertEnterpriseOrg(data *code.EnterpriseOrgForUpsert) (*common.CodeEnterpriseOrg, error) {
	var updated common.CodeEnterpriseOrg
	if err := c.MasterDB.
		Where("gitleaks_id=? and login=? and project_id=?", data.GitleaksId, data.Login, data.ProjectId).
		Assign(map[string]interface{}{
			"gitleaks_id": data.GitleaksId,
			"login":       data.Login,
			"project_id":  data.ProjectId,
		}).
		FirstOrCreate(&updated).
		Error; err != nil {
		return nil, err
	}
	return &common.CodeEnterpriseOrg{
		GitleaksID: updated.GitleaksID,
		Login:      updated.Login,
		ProjectID:  data.ProjectId,
		UpdatedAt:  updated.UpdatedAt,
		CreatedAt:  updated.CreatedAt,
	}, nil
}

const deleteEnterpriseOrg = `delete from code_enterprise_org where project_id=? and gitleaks_id=? and login=?`

func (c *codeRepository) DeleteEnterpriseOrg(projectID, gitleaksID uint32, login string) error {
	if err := c.MasterDB.Exec(deleteEnterpriseOrg, projectID, gitleaksID, login).Error; err != nil {
		return err
	}
	return nil
}
