package grpc

import (
	"time"

	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/proto/code"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func NewFindingClient(svcAddr string) (finding.FindingServiceClient, error) {
	conn, err := getGRPCConn(svcAddr)
	if err != nil {
		return nil, err
	}
	return finding.NewFindingServiceClient(conn), nil
}

func NewAlertClient(svcAddr string) (alert.AlertServiceClient, error) {
	conn, err := getGRPCConn(svcAddr)
	if err != nil {
		return nil, err
	}
	return alert.NewAlertServiceClient(conn), nil
}

func NewCodeClient(svcAddr string) (code.CodeServiceClient, error) {
	conn, err := getGRPCConn(svcAddr)
	if err != nil {
		return nil, err
	}
	return code.NewCodeServiceClient(conn), nil
}

func getGRPCConn(addr string) (*grpc.ClientConn, error) {
	// Note: OpenTelemetry interceptor is not added to avoid trace overhead
	// due to high frequency of gRPC calls
	// Connection timeout is set to 3 seconds to prevent indefinite connection attempts
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(grpc.ConnectParams{
			MinConnectTimeout: 3 * time.Second,
		}),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
