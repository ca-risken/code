package dependency

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

	CodeDependencyQueueName string `split_words:"true" default:"code-dependency"`
	CodeDependencyQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/code-dependency"`
	MaxNumberOfMessage      int32  `split_words:"true" default:"10"`
	WaitTimeSecond          int32  `split_words:"true" default:"20"`

	// dependency
	GithubDefaultToken string `required:"true" split_words:"true" default:"your-token-here"`
	TrivyPath          string `split_words:"true" default:"/usr/local/bin/trivy"`

	// scan settings
	LimitRepositorySizeKb int `required:"true" split_words:"true" default:"500000"` // 500MB

	// grpc
	CoreSvcAddr          string `split_words:"true" default:"core.core.svc.cluster.local:8080"`
	DataSourceAPISvcAddr string `required:"true" split_words:"true" default:"datasource-api.datasource.svc.cluster.local:8081"`

	// handler
	CodeDataKey string `split_words:"true" required:"true"`
}
