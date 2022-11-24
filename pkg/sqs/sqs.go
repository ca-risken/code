package sqs

import (
	"context"
	"fmt"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/go-sqs-poller/worker/v5"
)

type SQSConfig struct {
	Debug              string `default:"false"`
	AWSRegion          string `envconfig:"aws_region"    default:"ap-northeast-1"`
	SQSEndpoint        string `envconfig:"sqs_endpoint"  default:"http://queue.middleware.svc.cluster.local:9324"`
	QueueName          string `split_words:"true" default:"code-gitleaks"`
	QueueURL           string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/code-gitleaks"`
	MaxNumberOfMessage int32  `split_words:"true" default:"10"`
	WaitTimeSecond     int32  `split_words:"true" default:"20"`
}

func NewSQSConsumer(ctx context.Context, conf *SQSConfig, l logging.Logger) (*worker.Worker, error) {
	if conf.Debug == "true" {
		l.Level(logging.DebugLevel)
	}
	sqsClient, err := worker.CreateSqsClient(ctx, conf.AWSRegion, conf.SQSEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new SQS client, %w", err)
	}
	return &worker.Worker{
		Config: &worker.Config{
			QueueName:          conf.QueueName,
			QueueURL:           conf.QueueURL,
			MaxNumberOfMessage: conf.MaxNumberOfMessage,
			WaitTimeSecond:     conf.WaitTimeSecond,
		},
		Log:       l,
		SqsClient: sqsClient,
	}, nil
}
