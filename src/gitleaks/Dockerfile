FROM golang:1.16 as builder
WORKDIR /go/src/github.com/ca-risken/code/src/gitleaks/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/CyberAgent/*,github.com/ca-risken/*"
ARG ENV_INJECTOR_VERSION=v0.0.6
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp gitleaks /go/bin/

WORKDIR /go/src/github.com/gassara-kys
RUN git clone https://github.com/gassara-kys/env-injector.git -b ${ENV_INJECTOR_VERSION} \
    && cd env-injector \
    && go build \
    && cp env-injector /go/bin/

FROM alpine
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /go/bin/env-injector /usr/local/bin/
COPY --from=builder /go/bin/gitleaks /usr/local/gitleaks/bin/
ENV DEBUG= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    GITLEAKS_QUEUE_NAME= \
    GITLEAKS_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE=1 \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    ALERT_SVC_ADDR= \
    AWS_SVC_ADDR= \
    CODE_SVC_ADDR= \
    GITHUB_DEFAULT_TOKEN= \
    DATA_KEY= \
    LIMIT_REPOSITORY_SIZE_KB= \
    SEPERATE_SCAN_DAYS=30 \
    GITLEAKS_SCAN_THREADS=1 \
    TZ=Asia/Tokyo
WORKDIR /usr/local/gitleaks
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/gitleaks"]
