.PHONY: all install clean network fmt build doc
all: run

install:
	go get \
		google.golang.org/grpc \
		github.com/golang/protobuf/protoc-gen-go \
		github.com/grpc-ecosystem/go-grpc-middleware

clean:
	rm -f proto/**/*.pb.go
	rm -f doc/*.md

fmt: proto/**/*.proto
	clang-format -i proto/**/*.proto

doc: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--doc_out=markdown,README.md:doc \
		proto/**/*.proto;

build: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--go_out=plugins=grpc,paths=source_relative:proto \
		proto/**/*.proto;

go-test: build
	cd proto/code && go test ./...
	cd pkg/common && go test ./...
	cd src/code   && go test ./...

go-mod-tidy: build
	cd proto/code   && go mod tidy
	cd pkg/common   && go mod tidy
	cd src/code     && go mod tidy
	cd src/gitleaks && go mod tidy

go-mod-update:
	cd src/code \
		&& go get -u \
			github.com/CyberAgent/mimosa-code/...
	cd src/gitleaks \
		&& go get -u \
			github.com/CyberAgent/mimosa-code/...

# @see https://github.com/CyberAgent/mimosa-common/tree/master/local
network:
	@if [ -z "`docker network ls | grep local-shared`" ]; then docker network create local-shared; fi

run: go-test network
	. env.sh && docker-compose up -d --build

log:
	. env.sh && docker-compose logs -f

stop:
	. env.sh && docker-compose down
