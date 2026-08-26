GO ?= go

.PHONY: fmt build test test-integration test-e2e test-all

fmt:
	gofmt -l -w .

build:
	$(GO) build -o bin/kubegate ./cmd/kubegate

test:
	$(GO) test ./internal/... ./cmd/...

test-integration:
	$(GO) test -tags=integration ./test/integration/...

test-e2e:
	KUBEGATE_E2E=1 $(GO) test -tags=e2e -timeout=20m ./test/e2e/...

test-all: test test-integration test-e2e
