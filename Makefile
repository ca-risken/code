TARGETS = code gitleaks
BUILD_TARGETS = $(TARGETS:=.build)
BUILD_CI_TARGETS = $(TARGETS:=.build-ci)
IMAGE_PUSH_TARGETS = $(TARGETS:=.push-image)
MANIFEST_CREATE_TARGETS = $(TARGETS:=.create-manifest)
MANIFEST_PUSH_TARGETS = $(TARGETS:=.push-manifest)
TEST_TARGETS = $(TARGETS:=.go-test)
BUILD_OPT=""
IMAGE_TAG=latest
MANIFEST_TAG=latest
IMAGE_PREFIX=code
IMAGE_REGISTRY=local

PHONY: all
all: build

PHONY: install
install:
	go get \
		google.golang.org/grpc \
		github.com/golang/protobuf/protoc-gen-go \
		github.com/grpc-ecosystem/go-grpc-middleware

PHONY: clean
clean:
	rm -f proto/**/*.pb.go
	rm -f doc/*.md

PHONY: fmt
fmt: proto/**/*.proto
	clang-format -i proto/**/*.proto

PHONY: doc
doc: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--doc_out=markdown,README.md:doc \
		proto/**/*.proto;

PHONY: proto
proto: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--go_out=plugins=grpc,paths=source_relative:proto \
		proto/**/*.proto;

PHONY: build $(BUILD_TARGETS)
build: $(BUILD_TARGETS)
%.build: %.go-test
	. env.sh && TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh

PHONY: build-ci $(BUILD_CI_TARGETS)
build-ci: $(BUILD_CI_TARGETS)
%.build-ci:
	TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh
	docker tag $(IMAGE_PREFIX)/$(*):$(IMAGE_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

PHONY: push-image $(IMAGE_PUSH_TARGETS)
push-image: $(IMAGE_PUSH_TARGETS)
%.push-image:
	docker push $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

PHONY: create-manifest $(MANIFEST_CREATE_TARGETS)
create-manifest: $(MANIFEST_CREATE_TARGETS)
%.create-manifest:
	docker manifest create $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_amd64 $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_arm64
	docker manifest annotate --arch amd64 $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_amd64
	docker manifest annotate --arch arm64 $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_arm64

PHONY: push-manifest $(MANIFEST_PUSH_TARGETS)
push-manifest: $(MANIFEST_PUSH_TARGETS)
%.push-manifest:
	docker manifest push $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG)
	docker manifest inspect $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG)

PHONY: go-test $(TEST_TARGETS) proto-test pkg-test
go-test: $(TEST_TARGETS) proto-test pkg-test
%.go-test:
	cd src/$(*) && go test ./...
proto-test:
	cd proto/code && go test ./...
pkg-test:
	cd pkg/common && go test ./...

PHONY: go-mod-tidy
go-mod-tidy: proto
	cd proto/code   && go mod tidy
	cd pkg/common   && go mod tidy
	cd src/code     && go mod tidy
	cd src/gitleaks && go mod tidy

PHONY: go-mod-update
go-mod-update:
	cd src/code \
		&& go get -u \
			github.com/ca-risken/code/...
	cd src/gitleaks \
		&& go get -u \
			github.com/ca-risken/code/...

