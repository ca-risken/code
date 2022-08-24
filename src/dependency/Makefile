.PHONY: all run
all: run

run:
	ls *.go | grep -v '_test.go' | xargs go run

enque:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/code-dependency \
		--message-body '{"dependency_id":1001, "project_id":1001}'
