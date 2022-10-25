FROM golang:1.18.2 as builder
WORKDIR /go/src/github.com/ca-risken/code/src/dependency/

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/

FROM public.ecr.aws/risken/code/dependency-base:v0.0.1
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
    CORE_SVC_ADDR= \
    DATA_SOURCE_API_SVC_ADDR= \
    GITHUB_DEFAULT_TOKEN= \
    DATA_KEY= \
    LIMIT_REPOSITORY_SIZE_KB= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/dependency
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/dependency"]
