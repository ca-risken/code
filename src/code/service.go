package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"time"

	"github.com/CyberAgent/mimosa-code/pkg/common"
	"github.com/CyberAgent/mimosa-code/proto/code"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/jinzhu/gorm"
	"github.com/kelseyhightower/envconfig"
	"github.com/vikyd/zero"
)

type codeService struct {
	repository codeRepoInterface
	sqs        sqsAPI
	cipher     cipher.Block
}

type codeServiceConf struct {
	DataKey string `split_words:"true" required:"true"`
}

func newCodeService() code.CodeServiceServer {
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
		repository: newCodeRepository(),
		sqs:        newSQSClient(),
		cipher:     block,
	}
}

func (c *codeService) ListDataSource(ctx context.Context, req *code.ListDataSourceRequest) (*code.ListDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := c.repository.ListDataSource(req.CodeDataSourceId, req.Name)
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
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
		UpdatedAt:        data.CreatedAt.Unix(),
	}
}

func (c *codeService) ListGitleaks(ctx context.Context, req *code.ListGitleaksRequest) (*code.ListGitleaksResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := c.repository.ListGitleaks(req.ProjectId, req.CodeDataSourceId, req.GitleaksId)
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return &code.ListGitleaksResponse{}, nil
		}
		return nil, err
	}
	data := code.ListGitleaksResponse{}
	for _, d := range *list {
		data.Gitleaks = append(data.Gitleaks, convertGitleaks(&d))
	}
	return &data, nil
}

func (c *codeService) PutGitleaks(ctx context.Context, req *code.PutGitleaksRequest) (*code.PutGitleaksResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	registerd, err := c.repository.UpsertGitleaks(req.Gitleaks)
	if err != nil {
		return nil, err
	}
	return &code.PutGitleaksResponse{Gitleaks: convertGitleaks(registerd)}, nil
}

const maskData = "xxxxxxxxxx"

func convertGitleaks(data *common.CodeGitleaks) *code.Gitleaks {
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
		TargetResource:      data.TargetResource,
		RepositoryPattern:   data.RepositoryPattern,
		GithubUser:          data.GithubUser,
		PersonalAccessToken: data.PersonalAccessToken,
		GitleaksConfig:      data.GitleaksConfig,
		Status:              getStatus(data.Status),
		StatusDetail:        data.StatusDetail,
		CreatedAt:           data.CreatedAt.Unix(),
		UpdatedAt:           data.CreatedAt.Unix(),
	}
	if gitlekas.PersonalAccessToken != "" {
		gitlekas.PersonalAccessToken = maskData // Masking sensitive data.
	}
	if !zero.IsZeroVal(data.ScanAt) {
		gitlekas.ScanAt = data.ScanAt.Unix()
	}
	return &gitlekas
}

func (c *codeService) DeleteGitleaks(ctx context.Context, req *code.DeleteGitleaksRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	err := c.repository.DeleteGitleaks(req.ProjectId, req.GitleaksId)
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
	case code.Status_NOT_CONFIGURED.String():
		return code.Status_NOT_CONFIGURED
	case code.Status_ERROR.String():
		return code.Status_ERROR
	default:
		return code.Status_UNKNOWN
	}
}

func (c *codeService) InvokeScanGitleaks(ctx context.Context, req *code.InvokeScanGitleaksRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	data, err := c.repository.GetGitleaks(req.ProjectId, req.GitleaksId)
	if err != nil {
		return nil, err
	}
	resp, err := c.sqs.sendMsgForGitleaks(&common.GitleaksQueueMessage{
		GitleaksID: data.GitleaksID,
		ProjectID:  data.ProjectID,
	})
	if err != nil {
		return nil, err
	}
	appLogger.Infof("Invoke scanned, messageId: %v", resp.MessageId)
	return &empty.Empty{}, nil
}

func (c *codeService) InvokeScanAllGitleaks(ctx context.Context, _ *empty.Empty) (*empty.Empty, error) {
	list, err := c.repository.ListGitleaks(0, 0, 0)
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return &empty.Empty{}, nil
		}
		return nil, err
	}
	for _, g := range *list {
		if zero.IsZeroVal(g.ProjectID) || zero.IsZeroVal(g.CodeDataSourceID) {
			continue
		}
		if _, err := c.InvokeScanGitleaks(ctx, &code.InvokeScanGitleaksRequest{
			GitleaksId: g.GitleaksID,
			ProjectId:  g.ProjectID,
		}); err != nil {
			// エラーログはいて握りつぶす（すべてのスキャナ登録しきる）
			appLogger.Errorf("InvokeScanGitleaks error occured: gitleaks_id=%d, err=%+v", g.GitleaksID, err)
		}
		time.Sleep(time.Millisecond * 100) // jitter
	}
	return &empty.Empty{}, nil
}

func (c *codeService) encryptWithBase64(plainText string) (string, error) {
	buf, err := c.encrypt(plainText)
	if err != nil {
		appLogger.Error("Failed to encrypt data")
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

func (c *codeService) encrypt(plainText string) ([]byte, error) {
	// PKCS#7 Padding (CBCブロック暗号モードで暗号化したいので、長さが16byteの倍数じゃない場合は末尾をパディングしとく)
	padSize := aes.BlockSize - (len(plainText) % aes.BlockSize)
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	paddedText := append([]byte(plainText), pad...)

	encrypted := make([]byte, aes.BlockSize+len(paddedText))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		appLogger.Error("Failed to generate random Initial Vector")
		return encrypted, err
	}
	encrypter := cipher.NewCBCEncrypter(c.cipher, iv)
	encrypter.CryptBlocks(encrypted[aes.BlockSize:], []byte(paddedText))
	return encrypted, nil
}

func (c *codeService) decryptWithBase64(encrypted string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(encrypted)
	if err != nil {
		appLogger.Error("Failed to base64 decoded")
		return "", err
	}
	decrypted := c.decrypt(decoded)

	// Unpadding
	padSize := int(decrypted[len(decrypted)-1])
	return string(decrypted[:len(decrypted)-padSize]), nil
}

func (c *codeService) decrypt(encrypted []byte) []byte {
	iv := encrypted[:aes.BlockSize] // Get Initial Vector form first head block.
	decrypted := make([]byte, len(encrypted[aes.BlockSize:]))
	decrypter := cipher.NewCBCDecrypter(c.cipher, iv)
	decrypter.CryptBlocks(decrypted, encrypted[aes.BlockSize:])
	return decrypted
}