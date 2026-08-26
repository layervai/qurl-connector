export PATH := $(PATH):$(shell go env GOPATH)/bin
export GO111MODULE=on

# Version info injected at build time
BASE_VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "0.1.0")
BUILD_TIMESTAMP ?= $(shell date -u '+%y%m%d%H%M%S')
VERSION ?= $(BASE_VERSION).$(BUILD_TIMESTAMP)
GIT_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
# RFC3339 (UTC, `Z` suffix) keeps developer build metadata consistent.
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
VERSION_PKG = github.com/layervai/qurl-connector/pkg/version
LDFLAGS := -s -w \
  -X '$(VERSION_PKG).Version=$(VERSION)' \
  -X '$(VERSION_PKG).GitCommit=$(GIT_COMMIT)' \
  -X '$(VERSION_PKG).BuildDate=$(BUILD_DATE)'

BLUE := \033[34m
GREEN := \033[32m
RESET := \033[0m

.PHONY: all build frpc test test-race lint vet fmt clean verify-deps

all: print-version env frpc

build: frpc

print-version:
	@printf "$(BLUE)[qURL Connector] Start building...$(RESET)\n"
	@printf "$(BLUE)Version:     $(VERSION)$(RESET)\n"
	@printf "$(BLUE)Commit:      $(GIT_COMMIT)$(RESET)\n"
	@printf "$(BLUE)Build time:  $(BUILD_DATE)$(RESET)\n\n"

env:
	@go version

fmt:
	go fmt ./...

verify-deps:
	@./scripts/verify-frp-provenance.sh

lint:
	golangci-lint run ./pkg/... ./cmd/... ./internal/...

frpc:
	@printf "$(BLUE)[qURL Connector] Building developer command...$(RESET)\n"
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/qurl-connector ./cmd/frpc
	@printf "$(GREEN)[qURL Connector] developer command built -> $(CURDIR)/bin/qurl-connector$(RESET)\n"

test:
	CGO_ENABLED=0 go test -count=1 -coverprofile=coverage.out ./pkg/... ./cmd/... ./internal/...

# Race-detector lane. The race detector needs cgo, so this is the one test
# target that must NOT set CGO_ENABLED=0; the shipped binary and `make test`
# stay pure-Go. Kept separate so the canonical lane still proves the
# CGO_ENABLED=0 build works.
test-race:
	CGO_ENABLED=1 go test -race -count=1 ./pkg/... ./cmd/... ./internal/...

vet:
	go vet ./...

clean:
	rm -f ./bin/qurl-connector
	rm -f coverage.out
