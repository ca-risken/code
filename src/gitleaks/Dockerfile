FROM golang:1.16 as builder
WORKDIR /go/src/github.com/ca-risken/code/src/gitleaks/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/ca-risken/*"
RUN echo "machine github.com" > ~/.netrc
RUN --mount=type=secret,id=GITHUB_USER echo "login $(cat /run/secrets/GITHUB_USER)" >> ~/.netrc
RUN --mount=type=secret,id=GITHUB_TOKEN echo "password $(cat /run/secrets/GITHUB_TOKEN)" >> ~/.netrc
RUN go build && cp gitleaks /go/bin/

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/gitleaks /usr/local/gitleaks/bin/
ENV DEBUG= \
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
