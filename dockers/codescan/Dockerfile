FROM golang:1.23.0 AS builder
WORKDIR /go/src/github.com/ca-risken/code/
COPY code/go.mod .
COPY code/go.sum .
ENV GOTOOLCHAIN=auto
COPY code/ .
# Run go mod tidy, but ignore errors from test dependencies (opentelemetry internal package issues)
# The error is from test dependencies and doesn't affect the actual build
RUN go mod tidy || true
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/codescan cmd/codescan/main.go

FROM public.ecr.aws/risken/base/risken-base:v0.0.1 AS riskenbase

FROM returntocorp/semgrep:1.46.0
COPY --from=builder /go/bin/codescan /usr/local/codescan/bin/
COPY --from=riskenbase /usr/local/bin/env-injector /usr/local/bin/
RUN apk add git
ENV DEBUG= \
    TRACE_EXPORTER= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    CODE_CODE_SCAN_QUEUE_NAME= \
    CODE_CODE_SCAN_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE= \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    ALERT_SVC_ADDR= \
    CODE_SVC_ADDR= \
    GITHUB_DEFAULT_TOKEN= \
    DATA_KEY= \
    LIMIT_REPOSITORY_SIZE_KB= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/codescan
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/codescan"]
