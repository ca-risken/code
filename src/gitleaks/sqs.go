package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/gassara-kys/go-sqs-poller/worker/v4"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/vikyd/zero"
)

type sqsConfig struct {
	Debug string `default:"false"`

	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint"` // At local, set the endpoint url. e.g.)`http://localhost:9324`. But other environments do not set the value.

	GitleaksQueueName  string `split_words:"true" default:"code-gitleaks"`
	GitleaksQueueURL   string `split_words:"true" default:"http://localhost:9324/queue/code-gitleaks"`
	MaxNumberOfMessage int64  `split_words:"true" default:"10"`
	WaitTimeSecond     int64  `split_words:"true" default:"20"`
}

func newSQSConsumer() *worker.Worker {
	var conf sqsConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	if conf.Debug == "true" {
		appLogger.SetLevel(logrus.DebugLevel)
	}
	var sqsClient *sqs.SQS
	if !zero.IsZeroVal(&conf.SQSEndpoint) {
		sqsClient = sqs.New(session.New(), &aws.Config{
			Region:   &conf.AWSRegion,
			Endpoint: &conf.SQSEndpoint,
		})
	} else {
		sqsClient = sqs.New(session.New(), &aws.Config{
			Region: &conf.AWSRegion,
		})
	}
	return &worker.Worker{
		Config: &worker.Config{
			QueueName:          conf.GitleaksQueueName,
			QueueURL:           conf.GitleaksQueueURL,
			MaxNumberOfMessage: conf.MaxNumberOfMessage,
			WaitTimeSecond:     conf.WaitTimeSecond,
		},
		Log:       appLogger,
		SqsClient: sqsClient,
	}
}
