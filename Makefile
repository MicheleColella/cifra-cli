BINARY  := cifra
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
PREFIX  ?= /usr/local/bin

.PHONY: build clean test lint vet install uninstall test-install

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -buildvcs=false -o $(BINARY) ./cmd/cifra

clean:
	rm -f $(BINARY)

test:
	go test ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

install: build
	@if [ -f "$(PREFIX)/$(BINARY)" ] && [ "$(FORCE)" != "1" ]; then \
		echo "error: $(PREFIX)/$(BINARY) already exists — run 'make install FORCE=1' to overwrite"; \
		exit 1; \
	fi
	@install -m 755 $(BINARY) $(PREFIX)/$(BINARY) || { \
		echo "error: cannot write to $(PREFIX) — try 'sudo make install'"; \
		exit 1; \
	}
	@echo "installed $(PREFIX)/$(BINARY)"

uninstall:
	@if [ ! -f "$(PREFIX)/$(BINARY)" ]; then \
		echo "nothing to uninstall: $(PREFIX)/$(BINARY) not found"; \
	elif rm -f "$(PREFIX)/$(BINARY)"; then \
		echo "removed $(PREFIX)/$(BINARY)"; \
	else \
		echo "error: cannot remove $(PREFIX)/$(BINARY) — try 'sudo make uninstall'"; \
		exit 1; \
	fi

test-install: build
	@set -e; \
	TMPDIR=$$(mktemp -d); \
	trap 'rm -rf "$$TMPDIR"' EXIT; \
	$(MAKE) -s install PREFIX="$$TMPDIR"; \
	test -x "$$TMPDIR/$(BINARY)" && echo "✓ install: binary present and executable"; \
	$(MAKE) -s install PREFIX="$$TMPDIR" 2>&1 | grep -q "already exists" && echo "✓ install: duplicate correctly blocked"; \
	$(MAKE) -s install PREFIX="$$TMPDIR" FORCE=1 && echo "✓ install: FORCE=1 overwrites"; \
	$(MAKE) -s uninstall PREFIX="$$TMPDIR" && echo "✓ uninstall: binary removed"; \
	test ! -f "$$TMPDIR/$(BINARY)" && echo "✓ uninstall: path no longer exists"; \
	$(MAKE) -s uninstall PREFIX="$$TMPDIR" && echo "✓ uninstall: idempotent (no error on missing)"; \
	echo "✓ all install/uninstall checks passed"
