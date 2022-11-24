TARGETS = gitleaks dependency
BUILD_TARGETS = $(TARGETS:=.build)
BUILD_CI_TARGETS = $(TARGETS:=.build-ci)
IMAGE_PUSH_TARGETS = $(TARGETS:=.push-image)
IMAGE_PULL_TARGETS = $(TARGETS:=.pull-image)
IMAGE_TAG_TARGETS = $(TARGETS:=.tag-image)
MANIFEST_CREATE_TARGETS = $(TARGETS:=.create-manifest)
MANIFEST_PUSH_TARGETS = $(TARGETS:=.push-manifest)
TEST_TARGETS = $(TARGETS:=.go-test)
LINT_TARGETS = $(TARGETS:=.lint)
GO_MOD_TIDY_TARGETS = $(TARGETS:=.go-mod-tidy)
GO_MOD_UPDATE_TARGETS = $(TARGETS:=.go-mod-update)
BUILD_OPT=""
IMAGE_TAG=latest
MANIFEST_TAG=latest
IMAGE_PREFIX=code
IMAGE_REGISTRY=local

PHONY: all
all: build

PHONY: build $(BUILD_TARGETS)
build: $(BUILD_TARGETS)
%.build: go-test
	TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh

PHONY: build-ci $(BUILD_CI_TARGETS)
build-ci: $(BUILD_CI_TARGETS)
%.build-ci:
	TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh
	docker tag $(IMAGE_PREFIX)/$(*):$(IMAGE_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

PHONY: push-image $(IMAGE_PUSH_TARGETS)
push-image: $(IMAGE_PUSH_TARGETS)
%.push-image:
	docker push $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

PHONY: pull-image $(IMAGE_PULL_TARGETS)
pull-image: $(IMAGE_PULL_TARGETS)
%.pull-image:
	docker pull $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

PHONY: tag-image $(IMAGE_TAG_TARGETS)
tag-image: $(IMAGE_TAG_TARGETS)
%.tag-image:
	docker tag $(SOURCE_IMAGE_PREFIX)/$(*):$(SOURCE_IMAGE_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

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

PHONY: go-test
go-test:
	GO111MODULE=on go test ./...

.PHONY: lint
lint:
	GO111MODULE=on GOFLAGS=-buildvcs=false golangci-lint --timeout 5m run

.PHONY: enqueue-gitleaks
enqueue-gitleaks:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/code-gitleaks \
		--message-body '{"github_setting_id":1001, "project_id":1001, "full_scan":"true", "scan_only":"true"}'

.PHONY: enqueue-dependency
enqueue-dependency:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/code-dependency \
		--message-body '{"github_setting_id":1001, "project_id":1001, "scan_only":"true"}'

FAKE: