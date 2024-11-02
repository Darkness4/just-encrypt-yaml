golint := $(shell which golangci-lint)
ifeq ($(golint),)
golint := $(shell go env GOPATH)/bin/golangci-lint
endif

goreleaser := $(shell which goreleaser)
ifeq ($(goreleaser),)
goreleaser := $(shell go env GOPATH)/bin/goreleaser
endif

build:
	$(goreleaser) build --single-target --snapshot --clean

.PHONY: snapshot
snapshot: $(goreleaser)
	$(goreleaser) release --snapshot --clean

.PHONY: release
release: $(goreleaser)
	$(goreleaser) release --clean

.PHONY: unit
unit:
	go test -race -covermode=atomic -tags=unit -timeout=30s ./...

$(golint):
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

$(goreleaser):
	go install github.com/goreleaser/goreleaser/v2@latest

.PHONY: lint
lint: $(golint)
	$(golint) run ./...

.PHONY: clean
clean:
	rm -rf dist/
