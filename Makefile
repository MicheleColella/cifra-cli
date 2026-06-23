BINARY  := envault
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build clean test lint vet

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) ./cmd/envault

clean:
	rm -f $(BINARY)

test:
	go test ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...
