package main

import (
	"fmt"
	"net"

	"github.com/CyberAgent/mimosa-code/proto/code"
	"github.com/aws/aws-xray-sdk-go/xray"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type codeConfig struct {
	Port    string `default:"10001"`
	EnvName string `default:"default" split_words:"true"`
}

func main() {
	var conf codeConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	mimosaxray.InitXRay(xray.Config{})

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", conf.Port))
	if err != nil {
		appLogger.Fatal(err)
	}

	server := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpcmiddleware.ChainUnaryServer(
				xray.UnaryServerInterceptor(),
				mimosaxray.AnnotateEnvTracingUnaryServerInterceptor(conf.EnvName))))
	codeServer := newCodeService()
	code.RegisterCodeServiceServer(server, codeServer)

	reflection.Register(server) // enable reflection API
	appLogger.Infof("Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf("Failed to gRPC serve: %v", err)
	}
}
