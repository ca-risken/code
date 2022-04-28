package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/code/pkg/common"
	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "code"
	serviceName = "gitleaks"
	settingURL  = "https://docs.security-hub.jp/code/gitleaks_datasource/"
)

func getFullServiceName() string {
	return fmt.Sprintf("%s.%s", nameSpace, serviceName)
}

type AppConfig struct {
	EnvName         string   `default:"local" split_words:"true"`
	TraceExporter   string   `split_words:"true" default:"nop"`
	ProfileExporter string   `split_words:"true" default:"nop"`
	ProfileTypes    []string `split_words:"true"`
	TraceDebug      bool     `split_words:"true" default:"false"`

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

	pTypes, err := profiler.ConvertProfileTypeFrom(conf.ProfileTypes)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	pExporter, err := profiler.ConvertExporterTypeFrom(conf.ProfileExporter)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	pc := profiler.Config{
		ServiceName:  fmt.Sprintf("%s.%s", nameSpace, serviceName),
		EnvName:      conf.EnvName,
		ProfileTypes: pTypes,
		ExporterType: pExporter,
	}
	err = pc.Start()
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	defer pc.Stop()

	tc := &tracer.Config{
		ServiceName: getFullServiceName(),
		Environment: conf.EnvName,
		Debug:       conf.TraceDebug,
	}
	tracer.Start(tc)
	defer tracer.Stop()

	sqsConf := &SqsConfig{
		Debug:              conf.Debug,
		AWSRegion:          conf.AWSRegion,
		SQSEndpoint:        conf.SQSEndpoint,
		GitleaksQueueName:  conf.GitleaksQueueName,
		GitleaksQueueURL:   conf.GitleaksQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	f, err := mimosasqs.NewFinalizer(common.GitleaksDataSource, settingURL, conf.FindingSvcAddr, nil)
	if err != nil {
		appLogger.Fatalf("Failed to create Finalizer, err=%+v", err)
	}
	consumer := newSQSConsumer(sqsConf)
	appLogger.Info("Start the gitleaks SQS consumer server...")
	ctx := context.Background()
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.StatusLoggingHandler(appLogger,
					mimosasqs.TracingHandler(getFullServiceName(),
						f.FinalizeHandler(newHandler(&conf)))))))
}
