package main

import (
	"context"

	"github.com/aws/aws-xray-sdk-go/xray"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/trace"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "code"
	serviceName = "gitleaks"
)

type AppConfig struct {
	EnvName       string `default:"local" split_words:"true"`
	TraceExporter string `split_words:"true" default:"nop"`

	// sqs
	Debug string `default:"false"`

	AWSRegion   string `envconfig:"aws_region"    default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint"  default:"http://queue.middleware.svc.cluster.local:9324"`

	GitleaksQueueName  string `split_words:"true" default:"code-gitleaks"`
	GitleaksQueueURL   string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/code-gitleaks"`
	MaxNumberOfMessage int64  `split_words:"true" default:"10"`
	WaitTimeSecond     int64  `split_words:"true" default:"20"`

	// gitleaks
	GithubDefaultToken    string `required:"true" split_words:"true" default:"your-token-here"`
	LimitRepositorySizeKb int    `required:"true" split_words:"true" default:"500000"` // 500MB
	SeperateScanDays      int    `required:"true" split_words:"true" default:"365"`
	GitleaksScanThreads   int    `required:"true" split_words:"true" default:"1"`
	ScanOnMemory          bool   `split_words:"true" default:"false"`

	// grpc
	FindingSvcAddr string `split_words:"true" default:"finding.core.svc.cluster.local:8001"`
	AlertSvcAddr   string `split_words:"true"  default:"alert.core.svc.cluster.local:8004"`
	CodeSvcAddr    string `split_words:"true"  default:"code.code.svc.cluster.local:10001"`

	// handler
	DataKey string `split_words:"true" required:"true"`
}

func main() {
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	err = mimosaxray.InitXRay(xray.Config{})
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	tc := &trace.Config{
		Namespace:    nameSpace,
		ServiceName:  serviceName,
		Environment:  conf.EnvName,
		ExporterType: trace.GetExporterType(conf.TraceExporter),
	}
	ctx := context.Background()
	tp, err := trace.Init(ctx, tc)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			appLogger.Fatal(err.Error())
		}
	}()

	sqsConf := &SqsConfig{
		Debug:              conf.Debug,
		AWSRegion:          conf.AWSRegion,
		SQSEndpoint:        conf.SQSEndpoint,
		GitleaksQueueName:  conf.GitleaksQueueName,
		GitleaksQueueURL:   conf.GitleaksQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	consumer := newSQSConsumer(sqsConf)
	appLogger.Info("Start the gitleaks SQS consumer server...")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.StatusLoggingHandler(appLogger,
					mimosaxray.MessageTracingHandler(conf.EnvName, tc.GetFullServiceName(),
						trace.ProcessTracingHandler(tc.GetFullServiceName(), newHandler(&conf)))))))
}
