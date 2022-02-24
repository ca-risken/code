package main

import (
	"context"
	"fmt"
	"net"

	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/code/proto/code"
	"github.com/ca-risken/common/pkg/profiler"
	mimosarpc "github.com/ca-risken/common/pkg/rpc"
	"github.com/ca-risken/common/pkg/trace"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	"github.com/gassara-kys/envconfig"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	nameSpace   = "code"
	serviceName = "code"
)

type AppConfig struct {
	Port          string   `default:"10001"`
	EnvName       string   `default:"local" split_words:"true"`
	TraceExporter string   `split_words:"true" default:"nop"`
	UseProfiler   bool     `split_words:"true" default:"false"`
	ProfileTypes  []string `split_words:"true"`
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

	pTypes, err := profiler.ConvertFrom(conf.ProfileTypes)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	pc := profiler.Config{
		ServiceName:  fmt.Sprintf("%s.%s", nameSpace, serviceName),
		EnvName:      conf.EnvName,
		ProfileTypes: pTypes,
		UseDatadog:   conf.UseProfiler,
	}
	err = pc.Start()
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	defer pc.Stop()

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

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", conf.Port))
	if err != nil {
		appLogger.Fatal(err)
	}

	server := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpcmiddleware.ChainUnaryServer(
				mimosarpc.LoggingUnaryServerInterceptor(appLogger),
				xray.UnaryServerInterceptor(),
				mimosaxray.AnnotateEnvTracingUnaryServerInterceptor(conf.EnvName),
				otelgrpc.UnaryServerInterceptor())))
	codeServer := newCodeService()
	code.RegisterCodeServiceServer(server, codeServer)

	reflection.Register(server) // enable reflection API
	appLogger.Infof("Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf("Failed to gRPC serve: %v", err)
	}
}
