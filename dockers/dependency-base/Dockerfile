FROM golang:1.16 as builder
ENV CGO_ENABLED=0
ARG ENV_INJECTOR_VERSION=v0.0.6

WORKDIR /go/src/github.com/gassara-kys
RUN git clone https://github.com/gassara-kys/env-injector.git -b ${ENV_INJECTOR_VERSION} \
    && cd env-injector \
    && go build \
    && cp env-injector /go/bin/

FROM aquasec/trivy:0.31.2
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /go/bin/env-injector /usr/local/bin/
