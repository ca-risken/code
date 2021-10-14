package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/code/pkg/common"
	"github.com/gassara-kys/envconfig"
)

type sqsConfig struct {
	AWSRegion   string `envconfig:"aws_region"   default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	GitleaksQueueURL         string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/code-gitleaks"`
	GitleaksFullScanQueueURL string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/code-gitleaks-full-scan"`
}

type sqsAPI interface {
	sendMsgForGitleaks(ctx context.Context, msg *common.GitleaksQueueMessage, fullScan bool) (*sqs.SendMessageOutput, error)
}

type sqsClient struct {
	svc                      *sqs.SQS
	gitleaksQueueURL         string
	gitleaksFullScanQueueURL string
}

func newSQSClient() *sqsClient {
	var conf sqsConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		appLogger.Fatalf("Failed to create a new session, %v", err)
	}
	session := sqs.New(sess, &aws.Config{
		Region:   &conf.AWSRegion,
		Endpoint: &conf.SQSEndpoint,
	})
	xray.AWS(session.Client)
	return &sqsClient{
		svc:                      session,
		gitleaksQueueURL:         conf.GitleaksQueueURL,
		gitleaksFullScanQueueURL: conf.GitleaksFullScanQueueURL,
	}
}

func (s *sqsClient) sendMsgForGitleaks(ctx context.Context, msg *common.GitleaksQueueMessage, fullScan bool) (*sqs.SendMessageOutput, error) {
	buf, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse message, err=%+v", err)
	}
	queueUrl := s.gitleaksQueueURL
	if fullScan && s.gitleaksFullScanQueueURL != "" {
		queueUrl = s.gitleaksFullScanQueueURL
	}
	resp, err := s.svc.SendMessageWithContext(ctx, &sqs.SendMessageInput{
		MessageBody:  aws.String(string(buf)),
		QueueUrl:     aws.String(queueUrl),
		DelaySeconds: aws.Int64(1),
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
