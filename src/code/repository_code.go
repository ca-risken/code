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
	var updated common.CodeGitleaks
	if err := c.MasterDB.
		Where("gitleaks_id = ? and project_id ", data.GitleaksId, data.ProjectId).
		Assign(map[string]interface{}{
			"code_data_source_id":   data.CodeDataSourceId,
			"name":                  convertZeroValueToNull(data.Name),
			"project_id":            data.ProjectId,
			"type":                  data.Type.String(),
			"target_resource":       data.TargetResource,
			"repository_pattern":    convertZeroValueToNull(data.RepositoryPattern),
			"github_user":           convertZeroValueToNull(data.GithubUser),
			"personal_access_token": convertZeroValueToNull(data.PersonalAccessToken),
			"scan_public":           fmt.Sprintf("%t", data.ScanPublic),
			"scan_internal":         fmt.Sprintf("%t", data.ScanInternal),
			"scan_private":          fmt.Sprintf("%t", data.ScanPrivate),
			"gitleaks_config":       convertZeroValueToNull(data.GitleaksConfig),
			"status":                data.Status.String(),
			"status_detail":         convertZeroValueToNull(data.StatusDetail),
			"scan_at":               time.Unix(data.ScanAt, 0),
		}).
		FirstOrCreate(&updated).
		Error; err != nil {
		return nil, err
	}
	return &common.CodeGitleaks{
		GitleaksID:          updated.GitleaksID,
		CodeDataSourceID:    data.CodeDataSourceId,
		Name:                data.Name,
		ProjectID:           data.ProjectId,
		Type:                data.Type.String(),
		TargetResource:      data.TargetResource,
		RepositoryPattern:   data.RepositoryPattern,
		GithubUser:          data.GithubUser,
		PersonalAccessToken: data.PersonalAccessToken,
		GitleaksConfig:      data.GitleaksConfig,
		Status:              data.Status.String(),
		StatusDetail:        data.StatusDetail,
		ScanAt:              time.Unix(data.ScanAt, 0),
		UpdatedAt:           updated.UpdatedAt,
		CreatedAt:           updated.CreatedAt,
	}, nil
}

const deleteGitleaks = `delete from code_gitleaks where project_id = ? and gitleaks_id = ?`

func (c *codeRepository) DeleteGitleaks(projectID, gitleaksID uint32) error {
	if err := c.MasterDB.Exec(deleteGitleaks, projectID, gitleaksID).Error; err != nil {
		return err
	}
	return nil
}

const selectGetCodeGitleaks = `select * from code_gitleaks where project_id = ? and gitleaks_id = ?`

func (c *codeRepository) GetGitleaks(projectID, gitleaksID uint32) (*common.CodeGitleaks, error) {
	data := common.CodeGitleaks{}
	if err := c.SlaveDB.Raw(selectGetCodeGitleaks, projectID, gitleaksID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

func (c *codeRepository) ListEnterpriseOrg(projectID, gitleaksID uint32) (*[]common.CodeEnterpriseOrg, error) {
	query := `select * from code_enterprise_org where 1=1`
	var params []interface{}
	if !zero.IsZeroVal(projectID) {
		query += " and project_id = ?"
		params = append(params, projectID)
	}
	if !zero.IsZeroVal(gitleaksID) {
		query += " and gitleaks_id = ?"
		params = append(params, gitleaksID)
	}
	data := []common.CodeEnterpriseOrg{}
	if err := c.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
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
