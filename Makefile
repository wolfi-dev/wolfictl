# Some nice defines for the "make install" target
PREFIX ?= /usr
BINDIR ?= ${PREFIX}/bin

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

GOFILES ?= $(shell find . -type f -name '*.go' -not -path "./vendor/*")

# Set version variables for LDFLAGS
GIT_TAG ?= dirty-tag
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

SRCS = $(shell find . -iname "*.go")

PKG ?= sigs.k8s.io/release-utils/version
LDFLAGS=-buildid= -X $(PKG).gitVersion=$(GIT_VERSION) \
        -X $(PKG).gitCommit=$(GIT_HASH) \
        -X $(PKG).gitTreeState=$(GIT_TREESTATE) \
        -X $(PKG).buildDate=$(BUILD_DATE)

KO_DOCKER_REPO ?= ghcr.io/wolfi-dev/wolfictl
DIGEST ?=
BUILDFLAGS ?=

ifdef DEBUG
BUILDFLAGS := -gcflags "all=-N -l" $(BUILDFLAGS)
endif

##########
# default
##########

default: help

##########
# Build
##########

.PHONY: wolfictl
wolfictl: $(SRCS) ## Builds wolfictl
	go build -trimpath $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o $@ ./

.PHONY: install
install: wolfictl ## Installs wolfictl into BINDIR (default /usr/bin)
	install -Dm755 wolfictl ${DESTDIR}${BINDIR}/wolfictl

#####################
# lint / test section
#####################

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

.PHONY: golangci-lint
golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;\

	# Please keep the installed version in sync with .github/workflows/golangci-lint.yaml
	GOBIN=$(GOLANGCI_LINT_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.62.0 ;\

.PHONY: fmt
fmt: ## Format all go files
	@ $(MAKE) --no-print-directory log-$@
	goimports -w $(GOFILES)

.PHONY: checkfmt
checkfmt: SHELL := /usr/bin/env bash
checkfmt: ## Check formatting of all go files
	@ $(MAKE) --no-print-directory log-$@
 	$(shell test -z "$(shell gofmt -l $(GOFILES) | tee /dev/stderr)")
 	$(shell test -z "$(shell goimports -l $(GOFILES) | tee /dev/stderr)")

log-%:
	@grep -h -E '^$*:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk \
			'BEGIN { \
				FS = ":.*?## " \
			}; \
			{ \
				printf "\033[36m==> %s\033[0m\n", $$2 \
			}'

.PHONY: lint
lint: checkfmt golangci-lint ## Run linters and checks like golangci-lint
	$(GOLANGCI_LINT_BIN) run

.PHONY: test
test: integration ## Run go test

.PHONY: unit
unit: ## Run unit tests
	go test -v ./...

.PHONY: integration
integration: ## Run tests, including integration tests
	go test -v ./... -tags=integration

.PHONY: clean
clean: ## Clean the workspace
	rm -rf wolfictl
	rm -rf bin/
	rm -rf dist/

##################
# help
##################

help: ## Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort

bin/docs:
	go build -v -o bin/docs cmd/docs/*.go

.PHONY: docs
docs: bin/docs ## update docs
	@echo "Generating docs"
	@./bin/docs --target=./docs/cmd
	@./bin/docs --target=./docs/man/man1 --kind=man
	@rm -f ./bin/docs
