package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/go-sqs-poller/worker/v5"
)

type SqsConfig struct {
	Debug string

	AWSRegion   string
	SQSEndpoint string

	QueueName          string
	QueueURL           string
	MaxNumberOfMessage int32
	WaitTimeSecond     int32
}

func newSQSConsumer(ctx context.Context, conf *SqsConfig) (*worker.Worker, error) {
	if conf.Debug == "true" {
		appLogger.Level(logging.DebugLevel)
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
		Log:       appLogger,
		SqsClient: sqsClient,
	}, nil
}
