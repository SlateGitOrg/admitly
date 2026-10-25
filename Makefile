# admitly — every quality gate is reachable from `make check`.
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

GO            ?= go
GOFLAGS       ?= -p=3
export GOFLAGS
COVERAGE_MIN  ?= 80
ENVTEST_K8S   ?= 1.37.0
SETUP_ENVTEST ?= $(GO) run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.2

.PHONY: all build check fmt fmt-check vet lint test coverage envtest envtest-if-available \
        integration demo bench fuzz golden clean help

all: check

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-22s %s\n", $$1, $$2}'

build: ## build bin/admitly
	$(GO) build -trimpath -o bin/admitly ./cmd/admitly

check: fmt-check vet lint test coverage envtest-if-available ## all gates: format, vet, lint, tests, coverage, envtest (if assets present)
	@echo "make check: all gates passed"

fmt: ## format the code
	gofmt -w cmd internal policies test

fmt-check: ## fail if any file is not gofmt-formatted
	@out="$$(gofmt -l cmd internal policies test)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	@echo "fmt-check: ok"

vet: ## go vet, including the envtest build tag
	$(GO) vet ./...
	$(GO) vet -tags envtest ./test/...

lint: ## golangci-lint with zero warnings
	golangci-lint run ./...

test: ## unit, golden, property and integration tests (race detector on)
	$(GO) test -race -count=1 -coverpkg=./internal/...,./policies -coverprofile=coverage.out ./...

coverage: ## enforce the coverage threshold on internal packages
	@scripts/coverage.sh coverage.out $(COVERAGE_MIN)

envtest: ## run the envtest suite (downloads kube-apiserver/etcd if missing)
	@assets="$$($(SETUP_ENVTEST) use -i $(ENVTEST_K8S) -p path 2>/dev/null || $(SETUP_ENVTEST) use $(ENVTEST_K8S) -p path)"; \
	  KUBEBUILDER_ASSETS="$$assets" $(GO) test -tags envtest -count=1 -v ./test/envtest/

envtest-if-available: ## run envtest only if assets are already installed (offline-safe)
	@assets="$$($(SETUP_ENVTEST) use -i $(ENVTEST_K8S) -p path 2>/dev/null || true)"; \
	if [ -n "$$assets" ] && [ -x "$$assets/kube-apiserver" ]; then \
	  KUBEBUILDER_ASSETS="$$assets" $(GO) test -tags envtest -count=1 ./test/envtest/; \
	else echo "envtest: SKIPPED (no kube-apiserver $(ENVTEST_K8S) assets installed; run 'make envtest' to download)"; fi

integration: envtest ## alias: the integration suite is envtest (no Docker needed)

demo: build ## offline end-to-end demo against bundled fixtures
	@scripts/demo.sh

bench: build ## latency benchmarks: Go micro-benchmarks + end-to-end TLS loopback
	$(GO) test -run '^$$' -bench . -benchmem -benchtime 3000x ./internal/engine/ ./internal/server/
	$(GO) test -run '^$$' -bench Comprehension -benchtime 5x ./internal/celenv/
	./bin/admitly bench --requests 5000 --concurrency 8 --warmup 500

fuzz: ## short fuzzing session for the image reference parser, HTTP handler and quantity functions
	$(GO) test -run '^$$' -fuzz FuzzParse -fuzztime 30s ./internal/imageref/
	$(GO) test -run '^$$' -fuzz FuzzValidateHandler -fuzztime 30s ./internal/server/
	$(GO) test -run '^$$' -fuzz FuzzQuantity -fuzztime 30s ./internal/celenv/

golden: ## regenerate golden AdmissionReview responses (review the diff!)
	$(GO) test ./internal/server/ -run Golden -update

clean: ## remove build and test artifacts
	rm -rf bin coverage.out .demo
