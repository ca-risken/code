package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ca-risken/code/pkg/common"
	"github.com/ca-risken/code/proto/code"
	"github.com/ca-risken/core/proto/project"
	"github.com/gassara-kys/envconfig"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/vikyd/zero"
	"gorm.io/gorm"
)

type codeService struct {
	repository    codeRepoInterface
	sqs           sqsAPI
	cipherBlock   cipher.Block
	projectClient project.ProjectServiceClient
}

type codeServiceConf struct {
	DataKey string `split_words:"true" required:"true"`
}

func newCodeService(coreSvcAddr string) code.CodeServiceServer {
	var conf codeServiceConf
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	key := []byte(conf.DataKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	return &codeService{
		repository:    newCodeRepository(),
		sqs:           newSQSClient(),
		cipherBlock:   block,
		projectClient: newProjectClient(coreSvcAddr),
	}
}

func convertDataSource(data *common.CodeDataSource) *code.CodeDataSource {
	if data == nil {
		return &code.CodeDataSource{}
	}
	return &code.CodeDataSource{
		CodeDataSourceId: data.CodeDataSourceID,
		Name:             data.Name,
		Description:      data.Description,
		MaxScore:         data.MaxScore,
		CreatedAt:        data.CreatedAt.Unix(),
		UpdatedAt:        data.UpdatedAt.Unix(),
	}
}

func (c *codeService) ListDataSource(ctx context.Context, req *code.ListDataSourceRequest) (*code.ListDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := c.repository.ListDataSource(ctx, req.CodeDataSourceId, req.Name)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &code.ListDataSourceResponse{}, nil
		}
		return nil, err
	}
	data := code.ListDataSourceResponse{}
	for _, d := range *list {
		data.CodeDataSource = append(data.CodeDataSource, convertDataSource(&d))
	}
	return &data, nil
}

const maskData = "xxxxxxxxxx"

func convertGitleaks(data *common.CodeGitleaks, maskKey bool) *code.Gitleaks {
	var gitlekas code.Gitleaks
	if data == nil {
		return &gitlekas
	}
	gitlekas = code.Gitleaks{
		GitleaksId:          data.GitleaksID,
		CodeDataSourceId:    data.CodeDataSourceID,
		Name:                data.Name,
		ProjectId:           data.ProjectID,
		Type:                getType(data.Type),
		BaseUrl:             data.BaseURL,
		TargetResource:      data.TargetResource,
		RepositoryPattern:   data.RepositoryPattern,
		GithubUser:          data.GithubUser,
		PersonalAccessToken: data.PersonalAccessToken,
		ScanPublic:          data.ScanPublic,
		ScanInternal:        data.ScanInternal,
		ScanPrivate:         data.ScanPrivate,
		GitleaksConfig:      data.GitleaksConfig,
		Status:              getStatus(data.Status),
		StatusDetail:        data.StatusDetail,
		CreatedAt:           data.CreatedAt.Unix(),
		UpdatedAt:           data.UpdatedAt.Unix(),
	}
	if gitlekas.PersonalAccessToken != "" && maskKey {
		gitlekas.PersonalAccessToken = maskData // Masking sensitive data.
	}
	if !zero.IsZeroVal(data.ScanAt) {
		gitlekas.ScanAt = data.ScanAt.Unix()
	}
	if !zero.IsZeroVal(data.ScanSucceededAt) {
		gitlekas.ScanSucceededAt = data.ScanSucceededAt.Unix()
	}
	return &gitlekas
}

func (c *codeService) ListGitleaks(ctx context.Context, req *code.ListGitleaksRequest) (*code.ListGitleaksResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := c.repository.ListGitleaks(ctx, req.ProjectId, req.CodeDataSourceId, req.GitleaksId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &code.ListGitleaksResponse{}, nil
		}
		return nil, err
	}
	data := code.ListGitleaksResponse{}
	for _, d := range *list {
		data.Gitleaks = append(data.Gitleaks, convertGitleaks(&d, true))
	}
	return &data, nil
}

func (c *codeService) GetGitleaks(ctx context.Context, req *code.GetGitleaksRequest) (*code.GetGitleaksResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	data, err := c.repository.GetGitleaks(ctx, req.ProjectId, req.GitleaksId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &code.GetGitleaksResponse{}, nil
		}
		return nil, err
	}
	return &code.GetGitleaksResponse{Gitleaks: convertGitleaks(data, false)}, nil
}

func (c *codeService) PutGitleaks(ctx context.Context, req *code.PutGitleaksRequest) (*code.PutGitleaksResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if req.Gitleaks.PersonalAccessToken != "" && req.Gitleaks.PersonalAccessToken != maskData {
		encrypted, err := common.EncryptWithBase64(&c.cipherBlock, req.Gitleaks.PersonalAccessToken)
		if err != nil {
			appLogger.Errorf("Failed to encrypt PAT: err=%+v", err)
			return nil, err
		}
		req.Gitleaks.PersonalAccessToken = encrypted
	} else {
		req.Gitleaks.PersonalAccessToken = "" // for not update token.
	}
	registerd, err := c.repository.UpsertGitleaks(ctx, req.Gitleaks)
	if err != nil {
		return nil, err
	}
	return &code.PutGitleaksResponse{Gitleaks: convertGitleaks(registerd, true)}, nil
}

func (c *codeService) DeleteGitleaks(ctx context.Context, req *code.DeleteGitleaksRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	err := c.repository.DeleteGitleaks(ctx, req.ProjectId, req.GitleaksId)
	if err != nil {
		return nil, err
	}
	return &empty.Empty{}, nil
}

func getType(s string) code.Type {
	typeKey := strings.ToUpper(s)
	if _, ok := code.Type_value[typeKey]; !ok {
		return code.Type_UNKNOWN_TYPE
	}
	switch typeKey {
	case code.Type_ENTERPRISE.String():
		return code.Type_ENTERPRISE
	case code.Type_ORGANIZATION.String():
		return code.Type_ORGANIZATION
	case code.Type_USER.String():
		return code.Type_USER
	default:
		return code.Type_UNKNOWN_TYPE
	}
}

func getStatus(s string) code.Status {
	statusKey := strings.ToUpper(s)
	if _, ok := code.Status_value[statusKey]; !ok {
		return code.Status_UNKNOWN
	}
	switch statusKey {
	case code.Status_OK.String():
		return code.Status_OK
	case code.Status_CONFIGURED.String():
		return code.Status_CONFIGURED
	case code.Status_IN_PROGRESS.String():
		return code.Status_IN_PROGRESS
	case code.Status_ERROR.String():
		return code.Status_ERROR
	default:
		return code.Status_UNKNOWN
	}
}

func convertEnterpriseOrg(data *common.CodeEnterpriseOrg) *code.EnterpriseOrg {
	if data == nil {
		return &code.EnterpriseOrg{}
	}
	return &code.EnterpriseOrg{
		GitleaksId: data.GitleaksID,
		Login:      data.Login,
		ProjectId:  data.ProjectID,
		CreatedAt:  data.CreatedAt.Unix(),
		UpdatedAt:  data.CreatedAt.Unix(),
	}
}

func (c *codeService) ListEnterpriseOrg(ctx context.Context, req *code.ListEnterpriseOrgRequest) (*code.ListEnterpriseOrgResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := c.repository.ListEnterpriseOrg(ctx, req.ProjectId, req.GitleaksId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &code.ListEnterpriseOrgResponse{}, nil
		}
		return nil, err
	}
	data := code.ListEnterpriseOrgResponse{}
	for _, d := range *list {
		data.EnterpriseOrg = append(data.EnterpriseOrg, convertEnterpriseOrg(&d))
	}
	return &data, nil
}

func (c *codeService) PutEnterpriseOrg(ctx context.Context, req *code.PutEnterpriseOrgRequest) (*code.PutEnterpriseOrgResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	registerd, err := c.repository.UpsertEnterpriseOrg(ctx, req.EnterpriseOrg)
	if err != nil {
		return nil, err
	}
	return &code.PutEnterpriseOrgResponse{EnterpriseOrg: convertEnterpriseOrg(registerd)}, nil
}

func (c *codeService) DeleteEnterpriseOrg(ctx context.Context, req *code.DeleteEnterpriseOrgRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	err := c.repository.DeleteEnterpriseOrg(ctx, req.ProjectId, req.GitleaksId, req.Login)
	if err != nil {
		return nil, err
	}
	return &empty.Empty{}, nil
}

func (c *codeService) InvokeScanGitleaks(ctx context.Context, req *code.InvokeScanGitleaksRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	data, err := c.repository.GetGitleaks(ctx, req.ProjectId, req.GitleaksId)
	if err != nil {
		return nil, err
	}
	fullScan := false
	if data.ScanSucceededAt == nil {
		fullScan = true
	}
	resp, err := c.sqs.sendMsgForGitleaks(ctx, &common.GitleaksQueueMessage{
		GitleaksID: data.GitleaksID,
		ProjectID:  data.ProjectID,
		ScanOnly:   req.ScanOnly,
	}, fullScan)
	if err != nil {
		return nil, err
	}
	var scanSucceededAt int64
	if data.ScanSucceededAt != nil {
		scanSucceededAt = data.ScanSucceededAt.Unix()
	}
	if _, err = c.repository.UpsertGitleaks(ctx, &code.GitleaksForUpsert{
		GitleaksId:        data.GitleaksID,
		CodeDataSourceId:  data.CodeDataSourceID,
		Name:              data.Name,
		ProjectId:         data.ProjectID,
		Type:              getType(data.Type),
		BaseUrl:           data.BaseURL,
		TargetResource:    data.TargetResource,
		RepositoryPattern: data.RepositoryPattern,
		GithubUser:        data.GithubUser,
		// PersonalAccessToken :,
		ScanPublic:      data.ScanPublic,
		ScanInternal:    data.ScanInternal,
		ScanPrivate:     data.ScanPrivate,
		GitleaksConfig:  data.GitleaksConfig,
		Status:          code.Status_IN_PROGRESS,
		StatusDetail:    fmt.Sprintf("Start scan at %+v", time.Now().Format(time.RFC3339)),
		ScanAt:          data.ScanAt.Unix(),
		ScanSucceededAt: scanSucceededAt,
	}); err != nil {
		return nil, err
	}
	appLogger.Infof("Invoke scanned, messageId: %v", resp.MessageId)
	return &empty.Empty{}, nil
}

func (c *codeService) InvokeScanAllGitleaks(ctx context.Context, _ *empty.Empty) (*empty.Empty, error) {
	list, err := c.repository.ListGitleaks(ctx, 0, 0, 0)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &empty.Empty{}, nil
		}
		return nil, err
	}
	for _, g := range *list {
		if zero.IsZeroVal(g.ProjectID) || zero.IsZeroVal(g.CodeDataSourceID) {
			continue
		}
		if resp, err := c.projectClient.IsActive(ctx, &project.IsActiveRequest{ProjectId: g.ProjectID}); err != nil {
			appLogger.Errorf("Failed to project.IsActive API, err=%+v", err)
			return nil, err
		} else if !resp.Active {
			appLogger.Infof("Skip deactive project, project_id=%d", g.ProjectID)
			continue
		}
		if _, err := c.InvokeScanGitleaks(ctx, &code.InvokeScanGitleaksRequest{
			GitleaksId: g.GitleaksID,
			ProjectId:  g.ProjectID,
			ScanOnly:   true,
		}); err != nil {
			appLogger.Errorf("InvokeScanGitleaks error occured: gitleaks_id=%d, err=%+v", g.GitleaksID, err)
			return nil, err
		}
		// TODO delete jitter
		time.Sleep(time.Millisecond * 100) // jitter
	}
	return &empty.Empty{}, nil
}
