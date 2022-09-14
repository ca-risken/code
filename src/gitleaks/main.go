package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace            = "code"
	serviceName          = "gitleaks"
	settingURL           = "https://docs.security-hub.jp/code/gitleaks_datasource/"
	defaultGitleaksScore = 0.8
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

	CodeGitleaksQueueName string `split_words:"true" default:"code-gitleaks"`
	CodeGitleaksQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/code-gitleaks"`
	MaxNumberOfMessage    int32  `split_words:"true" default:"10"`
	WaitTimeSecond        int32  `split_words:"true" default:"20"`

	// gitleaks
	GithubDefaultToken string `required:"true" split_words:"true" default:"your-token-here"`
	Redact             bool   `split_words:"true" default:"true"`
	GitleaksConfigPath string `split_words:"true"`

	// scan settings
	LimitRepositorySizeKb int `required:"true" split_words:"true" default:"500000"` // 500MB

	// grpc
	CoreSvcAddr          string `split_words:"true" default:"core.core.svc.cluster.local:8080"`
	DataSourceAPISvcAddr string `required:"true" split_words:"true" default:"datasource-api.core.svc.cluster.local:8081"`

	// handler
	CodeDataKey string `split_words:"true" required:"true"`
}

func main() {
	ctx := context.Background()
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}

	pTypes, err := profiler.ConvertProfileTypeFrom(conf.ProfileTypes)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	pExporter, err := profiler.ConvertExporterTypeFrom(conf.ProfileExporter)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	pc := profiler.Config{
		ServiceName:  fmt.Sprintf("%s.%s", nameSpace, serviceName),
		EnvName:      conf.EnvName,
		ProfileTypes: pTypes,
		ExporterType: pExporter,
	}
	err = pc.Start()
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
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
		QueueName:          conf.CodeGitleaksQueueName,
		QueueURL:           conf.CodeGitleaksQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	f, err := mimosasqs.NewFinalizer(message.GitleaksDataSource, settingURL, conf.CoreSvcAddr, nil)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create Finalizer, err=%+v", err)
	}
	consumer, err := newSQSConsumer(ctx, sqsConf)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create SQS consumer, err=%+v", err)
	}
	handler, err := newHandler(ctx, &conf)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create Handler, err=%+v", err)
	}
	appLogger.Info(ctx, "Start the gitleaks SQS consumer server...")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.TracingHandler(getFullServiceName(),
					mimosasqs.StatusLoggingHandler(appLogger,
						f.FinalizeHandler(handler))))))
}
