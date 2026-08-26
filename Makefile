GO ?= go

.PHONY: fmt build test envtest test-integration test-e2e test-all

fmt:
	gofmt -l -w .

build:
	$(GO) build -o bin/kubegate ./cmd/kubegate

test:
	$(GO) test ./internal/... ./cmd/...

ENVTEST_K8S_VERSION ?= 1.31.0
ENVTEST := $(shell pwd)/bin/setup-envtest

envtest:
	GOBIN=$(shell pwd)/bin $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

test-integration: envtest
	KUBEBUILDER_ASSETS="$$($(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" \
		$(GO) test -tags=integration -timeout=10m ./test/integration/...

test-e2e:
	KUBEGATE_E2E=1 $(GO) test -tags=e2e -timeout=20m ./test/e2e/...

test-all: test test-integration test-e2e
