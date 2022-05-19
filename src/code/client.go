package main

import (
	"context"
	"time"

	"github.com/ca-risken/core/proto/project"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpctrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/google.golang.org/grpc"
)

func newProjectClient(coreSvcAddr string) project.ProjectServiceClient {
	ctx := context.Background()
	conn, err := getGRPCConn(ctx, coreSvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Faild to get GRPC connection: err=%+v", err)
	}
	return project.NewProjectServiceClient(conn)
}

func getGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithUnaryInterceptor(
			grpctrace.UnaryClientInterceptor()),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return conn, nil
}
