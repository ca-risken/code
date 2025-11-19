package grpc

import (
	"context"
	"time"

	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/proto/code"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func NewFindingClient(ctx context.Context, svcAddr string) (finding.FindingServiceClient, error) {
	conn, err := getGRPCConn(ctx, svcAddr)
	if err != nil {
		return nil, err
	}
	return finding.NewFindingServiceClient(conn), nil
}

func NewAlertClient(ctx context.Context, svcAddr string) (alert.AlertServiceClient, error) {
	conn, err := getGRPCConn(ctx, svcAddr)
	if err != nil {
		return nil, err
	}
	return alert.NewAlertServiceClient(conn), nil
}

func NewCodeClient(ctx context.Context, svcAddr string) (code.CodeServiceClient, error) {
	conn, err := getGRPCConn(ctx, svcAddr)
	if err != nil {
		return nil, err
	}
	return code.NewCodeServiceClient(conn), nil
}

func getGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	// Note: OpenTelemetry interceptor is not added to avoid trace overhead
	// due to high frequency of gRPC calls
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	connectCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		connectCtx, cancel = context.WithTimeout(ctx, 3*time.Second)
	}
	defer cancel()
	conn.Connect()
	if err := waitForReady(connectCtx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func waitForReady(ctx context.Context, conn *grpc.ClientConn) error {
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return nil
		}
		if !conn.WaitForStateChange(ctx, state) {
			return ctx.Err()
		}
	}
}
