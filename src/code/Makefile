####################################################
## grpcurl example
####################################################
.PHONY: all
all: help

.PHONY: help
help:
	@echo "Usage: make <sub-command>"
	@echo "\n---------------- sub-command list ----------------"
	@cat Makefile | grep -e "^.PHONY:" | grep -v "all" | cut -f2 -d' '

.PHONY: list-service
list-service:
	grpcurl -plaintext localhost:10001 list code.code.CodeService

.PHONY: list-datasource
list-datasource:
	grpcurl \
		-plaintext \
		-d '{"code_data_source_id":1001, "name":"code:gitleaks"}' \
		localhost:10001 code.code.CodeService.ListDataSource

.PHONY: list-gitleaks
list-gitleaks:
	grpcurl \
		-plaintext \
		-d '{"project_id": 1001, "code_data_source_id":1001, "gitleaks_id":1001}' \
		localhost:10001 code.code.CodeService.ListGitleaks

.PHONY: put-gitleaks
put-gitleaks:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "gitleaks": {"gitleaks_id":1002, "code_data_source_id":1001, "name":"test-gitleaks", "project_id":1001, "type":1, "target_resource":"CyberAgent/mimosa-code", "github_user":"mimosa-bot", "personal_access_token":"miomsa-bot-PAT", "status":1, "status_detail":"status detail", "scan_at": 1605816082}}' \
		localhost:10001 code.code.CodeService.PutGitleaks

.PHONY: delete-gitleaks
delete-gitleaks:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "gitleaks_id":1002}' \
		localhost:10001 code.code.CodeService.DeleteGitleaks

.PHONY: invoke-scan-gitleaks
invoke-scan-gitleaks:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "gitleaks_id":1001}' \
		localhost:10001 code.code.CodeService.InvokeScanGitleaks

.PHONY: invoke-scan-all-gitleaks
invoke-scan-all-gitleaks:
	grpcurl -plaintext localhost:10001 code.code.CodeService.InvokeScanAllGitleaks
