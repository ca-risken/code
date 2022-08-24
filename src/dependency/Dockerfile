FROM golang:1.17 as builder
WORKDIR /go/src/github.com/ca-risken/code/src/dependency/

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
ENV CGO_ENABLED=0
RUN go build && cp dependency /go/bin/

FROM public.ecr.aws/risken/code/dependency-base:v0.31.2
COPY --from=builder /go/bin/dependency /usr/local/dependency/bin/
ENV DEBUG= \
    TRACE_EXPORTER= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    DEPENDENCY_QUEUE_NAME= \
    DEPENDENCY_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE= \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    ALERT_SVC_ADDR= \
    AWS_SVC_ADDR= \
    CODE_SVC_ADDR= \
    GITHUB_DEFAULT_TOKEN= \
    DATA_KEY= \
    LIMIT_REPOSITORY_SIZE_KB= \
    SEPERATE_SCAN_DAYS= \
    DEPENDENCY_SCAN_THREADS= \
    SCAN_ON_MEMORY= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/dependency
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/dependency"]
