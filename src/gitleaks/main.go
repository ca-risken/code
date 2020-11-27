package main

import (
	"context"
)

func main() {
	ctx := context.Background()
	consumer := newSQSConsumer()
	appLogger.Info("Start the gitleaks SQS consumer server...")
	consumer.Start(ctx, newHandler())
}
