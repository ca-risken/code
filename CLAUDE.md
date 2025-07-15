# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

RISKEN Code is a security monitoring system for source code that consists of three microservices:
- **gitleaks**: Scans repositories for secrets and sensitive information
- **dependency**: Scans repositories for vulnerable dependencies using Trivy
- **codescan**: Performs static code analysis using Semgrep

Each service consumes messages from AWS SQS queues and reports findings via gRPC to the RISKEN core service.

## Essential Commands

### Build & Development

```bash
# Build all Docker images
make build

# Build specific service
make gitleaks.build
make dependency.build
make codescan.build

# Run all tests
make go-test

# Run tests for specific package
go test ./pkg/gitleaks/...

# Run linter (golangci-lint with 5m timeout)
make lint

# Install dependencies
make install
```

### Local Testing with SQS

```bash
# Send test messages to SQS queues
make enqueue-gitleaks
make enqueue-dependency
make enqueue-codescan
```

### Docker Operations

```bash
# Push images to registry
make push-image

# Tag images with new tags
make tag-image

# Create multi-arch manifests
make create-manifest
```

## Architecture

### Service Structure

Each service follows this pattern:
1. Main entry point in `cmd/{service}/main.go`
2. Business logic in `pkg/{service}/`
3. SQS handler processes messages from queue
4. Reports findings via gRPC clients

### Key Components

- **SQS Consumer** (`pkg/sqs/sqs.go`): Handles message polling and processing
- **gRPC Clients** (`pkg/grpc/client.go`): Communicates with core services
- **GitHub Integration** (`pkg/github/`): Repository access and scanning
- **Crypto** (`pkg/common/crypto.go`): AES encryption for sensitive data

### Service Communication

Services communicate with:
- **Core Service**: `core.core.svc.cluster.local:8080`
- **DataSource API**: `datasource-api.datasource.svc.cluster.local:8081`
- **SQS Endpoint**: `http://queue.middleware.svc.cluster.local:9324` (local)

### Message Flow

1. SQS message received with scan request
2. Service fetches GitHub settings from DataSource API
3. Repository is cloned/accessed
4. Scanner runs (Gitleaks/Trivy/Semgrep)
5. Findings are sent to Core Service via gRPC
6. Alerts are triggered based on rules

## Key Configuration

Environment variables for all services:
- `ENV_NAME`: Environment name (default: "local")
- `CODE_DATA_KEY`: Encryption key for sensitive data
- `TRACE_EXPORTER`: Tracing configuration
- `PROFILE_EXPORTER`: Profiling configuration

Service-specific:
- **Gitleaks**: `GITHUB_DEFAULT_TOKEN`, `REDACT`, `GITLEAKS_CONFIG_PATH`
- **Dependency**: `TRIVY_PATH`, `VULNERABILITY_API_URL`
- **Codescan**: Uses Semgrep for analysis

## Testing Approach

- Unit tests exist for each package following Go conventions (`*_test.go`)
- Tests use standard Go testing package
- No integration test framework - services are tested via SQS message injection
- Mock clients are used for gRPC testing

## Important Notes

1. **Encryption**: Personal access tokens are encrypted using AES cipher from `pkg/common/crypto.go`
2. **Repository Limits**: Default max repository size is 500MB
3. **Error Handling**: Services implement retry logic with non-retryable error detection
4. **Tracing**: Distributed tracing is built-in with configurable exporters

## Development Tips

1. When modifying SQS handlers, test locally using `make enqueue-*` commands
2. Each service can be developed independently but shares common packages
3. gRPC interfaces are defined in the main RISKEN repository (not in this repo)
4. Use existing patterns from other services when adding new scanners