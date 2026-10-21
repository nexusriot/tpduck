# tpduck build and packaging
#
# Common targets:
#   make build            build ./bin/tpduck for this machine
#   make test             unit + integration tests
#   make e2e              hermetic end-to-end tests in a container
#   make dist             cross-compiled tarballs in ./dist
#   make packages         .deb and .rpm in ./dist
#   make install          install to $(PREFIX) (default /usr/local)

SHELL := /bin/bash
.DEFAULT_GOAL := build

BINARY      := tpduck
PKG         := github.com/nexusriot/tpduck
MAIN        := ./cmd/tpduck
BIN_DIR     := bin
DIST_DIR    := dist
PREFIX      ?= /usr/local
DESTDIR     ?=

# internal/version/VERSION is the single source of truth; it is also embedded
# in the binary, so `go install` reports the same thing this does. A release
# overrides VERSION on the command line with the tag being built.
VERSION_FILE := internal/version/VERSION
VERSION     ?= $(shell cat $(VERSION_FILE) 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Static, reproducible-ish builds: no cgo, trimmed paths, no symbol table.
LDFLAGS     := -s -w -X $(PKG)/internal/version.Override=$(VERSION)
GOFLAGS     := -trimpath
export CGO_ENABLED ?= 0

# Platforms for `make dist` and `make packages`.
PLATFORMS   ?= linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
PKG_ARCHES  ?= amd64 arm64

.PHONY: help
help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST)

## build        build the binary for this machine
.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(MAIN)
	@echo "built $(BIN_DIR)/$(BINARY) ($(VERSION))"

## build-pcsc   build with YubiKey support (needs cgo + libpcsclite-dev)
.PHONY: build-pcsc
build-pcsc:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build $(GOFLAGS) -tags pcsc -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY)-pcsc $(MAIN)
	@echo "built $(BIN_DIR)/$(BINARY)-pcsc"

## test         run unit and integration tests
.PHONY: test
test:
	go test ./... -count=1

## race         run the tests under the race detector
.PHONY: race
race:
	CGO_ENABLED=1 go test ./... -race -count=1   # -race needs cgo

## vet          go vet
.PHONY: vet
vet:
	go vet ./...

## fmt          gofmt the tree
.PHONY: fmt
fmt:
	gofmt -w ./cmd ./internal ./tests

## check        fmt check + vet + race tests
.PHONY: check
check: vet
	@out=$$(gofmt -l ./cmd ./internal ./tests); \
	 if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(MAKE) race

## e2e          hermetic end-to-end tests inside a container
.PHONY: e2e
e2e:
	./scripts/e2e.sh

## e2e-pcsc     end-to-end smart-card tests against a virtual YubiKey
.PHONY: e2e-pcsc
e2e-pcsc:
	./scripts/e2e-pcsc.sh

## e2e-all      both end-to-end suites
.PHONY: e2e-all
e2e-all: e2e e2e-pcsc

## dist         cross-compiled tarballs + checksums in ./dist
.PHONY: dist
dist:
	VERSION=$(VERSION) PLATFORMS="$(PLATFORMS)" ./scripts/build.sh

## packages     .deb and .rpm in ./dist
.PHONY: packages
packages: dist
	VERSION=$(VERSION) ARCHES="$(PKG_ARCHES)" FLAVOUR=default ./scripts/package.sh

## dist-pcsc    smart-card build (needs libpcsclite-dev) in ./dist/pcsc
.PHONY: dist-pcsc
dist-pcsc:
	VERSION=$(VERSION) ./scripts/build-pcsc.sh

## packages-pcsc  tpduck-pcsc .deb and .rpm, depending on libpcsclite
.PHONY: packages-pcsc
packages-pcsc: dist-pcsc
	VERSION=$(VERSION) DIST_DIR=dist/pcsc ARCHES="$$(go env GOARCH)" FLAVOUR=pcsc ./scripts/package.sh

## deps         install the Linux build and runtime dependencies
.PHONY: deps
deps:
	./scripts/install-deps.sh

## deb          .deb packages only
.PHONY: deb
deb: dist
	VERSION=$(VERSION) ARCHES="$(PKG_ARCHES)" FORMATS=deb ./scripts/package.sh

## rpm          .rpm packages only
.PHONY: rpm
rpm: dist
	VERSION=$(VERSION) ARCHES="$(PKG_ARCHES)" FORMATS=rpm ./scripts/package.sh

## install      install binary, man page and completions under $(PREFIX)
.PHONY: install
install: build
	install -Dm0755 $(BIN_DIR)/$(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -Dm0644 docs/$(BINARY).1 $(DESTDIR)$(PREFIX)/share/man/man1/$(BINARY).1
	@# Staged in the build directory, not /tmp: this target is usually run
	@# under sudo, and a predictable /tmp path is a symlink waiting to happen.
	$(BIN_DIR)/$(BINARY) completion bash > $(BIN_DIR)/$(BINARY).bash
	install -Dm0644 $(BIN_DIR)/$(BINARY).bash $(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(BINARY)
	$(BIN_DIR)/$(BINARY) completion zsh > $(BIN_DIR)/_$(BINARY)
	install -Dm0644 $(BIN_DIR)/_$(BINARY) $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_$(BINARY)
	$(BIN_DIR)/$(BINARY) completion fish > $(BIN_DIR)/$(BINARY).fish
	install -Dm0644 $(BIN_DIR)/$(BINARY).fish $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/$(BINARY).fish
	@rm -f $(BIN_DIR)/$(BINARY).bash $(BIN_DIR)/_$(BINARY) $(BIN_DIR)/$(BINARY).fish
	@echo "installed to $(DESTDIR)$(PREFIX)"

## uninstall    remove what install placed
.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/$(BINARY).1
	rm -f $(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(BINARY)
	rm -f $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_$(BINARY)
	rm -f $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/$(BINARY).fish

## clean        remove build output
.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

## version      print the version this build would use
.PHONY: version
version:
	@echo $(VERSION)

## bump         set the version, e.g. make bump V=0.5.0
.PHONY: bump
bump:
	@test -n "$(V)" || { echo "usage: make bump V=0.5.0"; exit 1; }
	@echo "$(V)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+].*)?$$' \
	  || { echo "version must look like 1.2.3"; exit 1; }
	@printf '%s\n' "$(V)" > $(VERSION_FILE)
	@echo "version is now $$(cat $(VERSION_FILE))"
	@echo "remember: README install examples quote the version too"
