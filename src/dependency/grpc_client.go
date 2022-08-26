package main

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func getGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	// gRPCクライアントの呼び出し回数が非常に多くトレーシング情報の送信がエラーになるため、トレースは無効にしておく
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return conn, nil
}
