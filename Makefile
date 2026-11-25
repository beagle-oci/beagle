BINARY  := beagle
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

REGISTRY ?= localhost:5050
OLAREG   := github.com/olareg/olareg/cmd/olareg@v0.2.2

.PHONY: all build install run test test-race lint golangci fmt tidy registry registry-noreferrers seed clean

all: lint test build

build: ## Build bin/beagle
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/beagle

install: ## Install beagle into GOBIN
	go install -ldflags "$(LDFLAGS)" ./cmd/beagle

run: build ## Run beagle against $(REGISTRY)
	./bin/$(BINARY) $(REGISTRY)

test: ## Run unit tests
	go test ./...

test-race: ## Run unit tests with the race detector
	go test -race -count=1 ./...

lint: ## go vet + gofmt check
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:" && gofmt -l . && exit 1)

golangci: ## Run golangci-lint (must be built with Go >= 1.26)
	golangci-lint run

fmt: ## Format all Go files
	gofmt -w .

tidy: ## Tidy go.mod / go.sum
	go mod tidy

registry: ## Start an in-memory OCI registry with the referrers API on :5050
	go run $(OLAREG) serve --addr 127.0.0.1 --port 5050 --store-type mem

registry-noreferrers: ## Start a registry without the referrers API on :5051 (tag fallback)
	go run $(OLAREG) serve --addr 127.0.0.1 --port 5051 --store-type mem --api-referrer=false --api-delete

seed: ## Push demo content (images, signatures, SBOMs, charts) to $(REGISTRY)
	go run ./hack/seed $(REGISTRY)

clean:
	rm -rf bin/
