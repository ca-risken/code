FROM golang:1.17 as builder
WORKDIR /go/src/github.com/ca-risken/code/src/code/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/ca-risken/*"
RUN echo "machine github.com" > ~/.netrc
RUN --mount=type=secret,id=GITHUB_USER echo "login $(cat /run/secrets/GITHUB_USER)" >> ~/.netrc
RUN --mount=type=secret,id=GITHUB_TOKEN echo "password $(cat /run/secrets/GITHUB_TOKEN)" >> ~/.netrc
RUN go build && cp code /go/bin/

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/code /usr/local/code/bin/
ENV PORT= \
    DB_MASTER_HOST= \
    DB_MASTER_USER= \
    DB_MASTER_PASSWORD= \
    DB_SLAVE_HOST= \
    DB_SLAVE_USER= \
    DB_SLAVE_PASSWORD= \
    DB_SCHEMA=mimosa \
    DB_PORT=3306 \
    DB_LOG_MODE=false \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    GITLEAKS_QUEUE_URL= \
    GITLEAKS_FULL_SCAN_QUEUE_URL= \
    DATA_KEY= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/code
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/code"]
