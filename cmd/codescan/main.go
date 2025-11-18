package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/code/pkg/codescan"
	"github.com/ca-risken/code/pkg/grpc"
	"github.com/ca-risken/code/pkg/sqs"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "code"
	serviceName = "codescan"
)

var (
	appLogger            = logging.NewLogger()
	samplingRate float64 = 0.3000
)

func getFullServiceName() string {
	return fmt.Sprintf("%s.%s", nameSpace, serviceName)
}

type AppConfig struct {
	Debug           string   `default:"false"`
	EnvName         string   `default:"local" split_words:"true"`
	TraceExporter   string   `split_words:"true" default:"nop"`
	ProfileExporter string   `split_words:"true" default:"nop"`
	ProfileTypes    []string `split_words:"true"`
	TraceDebug      bool     `split_words:"true" default:"false"`

	// sqs
	AWSRegion   string `envconfig:"aws_region"    default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint"  default:"http://queue.middleware.svc.cluster.local:9324"`

	CodeCodeScanQueueName string `split_words:"true" default:"code-codescan"`
	CodeCodeScanQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/code-codescan"`
	MaxNumberOfMessage    int32  `split_words:"true" default:"10"`
	WaitTimeSecond        int32  `split_words:"true" default:"20"`

	// codescan
	GithubDefaultToken string `required:"true" split_words:"true" default:"your-token-here"`

	// scan settings
	LimitRepositorySizeKb int `required:"true" split_words:"true" default:"500000"` // 500MB

	// grpc
	CoreSvcAddr          string `split_words:"true" default:"core.core.svc.cluster.local:8080"`
	DataSourceAPISvcAddr string `required:"true" split_words:"true" default:"datasource-api.datasource.svc.cluster.local:8081"`

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
		ServiceName:  getFullServiceName(),
		Environment:  conf.EnvName,
		Debug:        conf.TraceDebug,
		SamplingRate: &samplingRate,
	}
	tracer.Start(tc)
	defer tracer.Stop()

	fc, err := grpc.NewFindingClient(ctx, conf.CoreSvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "failed to create finding client, err=%+v", err)
	}
	ac, err := grpc.NewAlertClient(ctx, conf.CoreSvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "failed to create alert client, err=%+v", err)
	}
	cc, err := grpc.NewCodeClient(ctx, conf.DataSourceAPISvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "failed to create alert client, err=%+v", err)
	}
	handler, err := codescan.NewHandler(
		ctx,
		fc,
		ac,
		cc,
		conf.CodeDataKey,
		conf.GithubDefaultToken,
		conf.LimitRepositorySizeKb,
		appLogger,
	)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create Handler, err=%+v", err)
	}

	sqsConf := &sqs.SQSConfig{
		Debug:              conf.Debug,
		AWSRegion:          conf.AWSRegion,
		SQSEndpoint:        conf.SQSEndpoint,
		QueueName:          conf.CodeCodeScanQueueName,
		QueueURL:           conf.CodeCodeScanQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	consumer, err := sqs.NewSQSConsumer(ctx, sqsConf, appLogger)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create SQS consumer, err=%+v", err)
	}
	appLogger.Info(ctx, "Start the code scan SQS consumer server...")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.TracingHandler(getFullServiceName(),
					mimosasqs.StatusLoggingHandler(appLogger, handler)))))
}
