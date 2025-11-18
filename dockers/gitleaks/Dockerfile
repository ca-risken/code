FROM golang:1.23.0 AS builder
WORKDIR /go/src/github.com/ca-risken/code/
COPY go.mod .
COPY go.sum .
ENV GOTOOLCHAIN=auto
COPY . .
# Tidy module dependencies without loading test-only deps (which pull non-existent OTel internals)
RUN go mod tidy -test=false \
	&& go mod verify
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/gitleaks cmd/gitleaks/main.go

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/gitleaks /usr/local/gitleaks/bin/
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
    GITLEAKS_QUEUE_NAME= \
    GITLEAKS_QUEUE_URL= \
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
    GITLEAKS_SCAN_THREADS= \
    SCAN_ON_MEMORY= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/gitleaks
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/gitleaks"]
