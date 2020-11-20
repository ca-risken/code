package main

import (
	"encoding/json"
	"fmt"

	"github.com/CyberAgent/mimosa-code/pkg/common"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/kelseyhightower/envconfig"
)

type sqsConfig struct {
	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://localhost:9324"`

	GitleaksQueueURL string `split_words:"true" required:"true"`
}

type sqsAPI interface {
	sendMsgForGitleaks(msg *common.GitleaksQueueMessage) (*sqs.SendMessageOutput, error)
}

type sqsClient struct {
	svc              *sqs.SQS
	gitleaksQueueURL string
}

func newSQSClient() *sqsClient {
	var conf sqsConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	session := sqs.New(session.New(), &aws.Config{
		Region:   &conf.AWSRegion,
		Endpoint: &conf.SQSEndpoint,
	})

	return &sqsClient{
		svc:              session,
		gitleaksQueueURL: conf.GitleaksQueueURL,
	}
}

func (s *sqsClient) sendMsgForGitleaks(msg *common.GitleaksQueueMessage) (*sqs.SendMessageOutput, error) {
	buf, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse message, err=%+v", err)
	}
	resp, err := s.svc.SendMessage(&sqs.SendMessageInput{
		MessageBody:  aws.String(string(buf)),
		QueueUrl:     aws.String(s.gitleaksQueueURL),
		DelaySeconds: aws.Int64(1),
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}