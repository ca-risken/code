#!/bin/bash -e

# github
export GITHUB_USER="your-name"
export GITHUB_TOKEN="your-token"

# GO
export GOPRIVATE="github.com/CyberAgent/*"

# DB
export DB_MASTER_HOST="db"
export DB_MASTER_USER="hoge"
export DB_MASTER_PASSWORD="moge"
export DB_SLAVE_HOST="db"
export DB_SLAVE_USER="hoge"
export DB_SLAVE_PASSWORD="moge"
export DB_LOG_MODE="false"

# CODE
export PORT="10001"
export DATA_KEY="12345678901234567890123456789012"
export AWS_REGION="ap-northeast-1"
export SQS_ENDPOINT="http://sqs:9324"
export GITLEAKS_QUEUE_NAME="code-gitleaks"
export GITLEAKS_QUEUE_URL="http://sqs:9324/queue/code-gitleaks"
export GITHUB_DEFAULT_TOKEN="your-token"

# gRPC server
export FINDING_SVC_ADDR="finding:8001"
export ALERT_SVC_ADDR="alert:8004"
export CODE_SVC_ADDR="code:10001"
