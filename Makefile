SHELL := /bin/bash
GO ?= go
GOBIN ?= $(shell $(GO) env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

MODULE := github.com/bshlisky/tetragon-relay
VERSION ?= $(shell git -C $(CURDIR) describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X 'main.version=$(VERSION)'

COVER_PKGS := ./internal/dsse/... ./internal/strictjson/... ./internal/trust/... ./internal/verify/...

.PHONY: all
all: ci

.PHONY: build
build:
	$(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/relayd ./cmd/relayd

.PHONY: test
test:
	$(GO) test -count=1 ./...

.PHONY: test-race
test-race:
	$(GO) test -race -count=1 -cover ./...

.PHONY: coverage
coverage:
	@fail=0; \
	for pkg in internal/dsse internal/strictjson internal/trust internal/verify; do \
		echo "== $$pkg =="; \
		$(GO) test -count=1 -covermode=count -coverprofile=/tmp/tetragon-relay-$$(basename $$pkg).out ./$$pkg/... >/dev/null; \
		line=$$($(GO) tool cover -func=/tmp/tetragon-relay-$$(basename $$pkg).out | tail -1); \
		echo "$$line"; \
		pct=$$(echo "$$line" | awk '{print $$NF}' | tr -d '%'); \
		awk -v p="$$pct" 'BEGIN { exit !(p+0 >= 95) }' || { echo "$$pkg coverage $$pct% is below the required 95%"; fail=1; }; \
	done; \
	exit $$fail

.PHONY: fuzz-short
fuzz-short:
	$(GO) test -run=NONE -fuzz=FuzzStrictJSON -fuzztime=60s ./internal/strictjson/...
	$(GO) test -run=NONE -fuzz=FuzzVerifyEnvelope -fuzztime=60s ./internal/verify/...
	$(GO) test -run=NONE -fuzz=FuzzRootUpdate -fuzztime=60s ./internal/trust/...

.PHONY: lint
lint:
	gofmt -l $$(find . -name '*.go' -not -path './vendor/*' -not -path './api/*') | tee /tmp/gofmt-out; test ! -s /tmp/gofmt-out
	goimports -l $$(find . -name '*.go' -not -path './vendor/*' -not -path './api/*') | tee /tmp/goimports-out; test ! -s /tmp/goimports-out
	$(GO) vet ./...
	golangci-lint run ./...

.PHONY: vuln
vuln:
	govulncheck ./...

.PHONY: sbom
sbom:
	@mkdir -p dist
	syft dir:. --source-name tetragon-relay --source-version $(VERSION) -o spdx-json=dist/sbom.spdx.json

.PHONY: proto
proto:
	buf generate
	@git diff --exit-code -- api/ || (echo "api/ is not up to date with control.proto; run 'make proto' and commit the result" && exit 1)

# PROTO_BASELINE is the commit the control protocol is allowed to make
# breaking changes against going forward (step 1 review A8; see
# docs/decisions/0010-proto-breaking-change-baseline.md). Before that
# commit, the proto was unreleased and changed freely across steps. This is
# set to the commit that lands the A8 rewrite itself, once it exists; see
# that ADR and docs/reports/step-02.md for the actual SHA.
PROTO_BASELINE := 54e450a68b786971ba20ff15d1febc15113a5921

.PHONY: breaking
breaking:
	buf breaking --against ".git#ref=$(PROTO_BASELINE)"

.PHONY: gen-vectors
gen-vectors:
	$(GO) run -tags testtools ./cmd/bundlesign-test -out testdata/vectors

.PHONY: verify-repro
verify-repro:
	@set -e; \
	dir1=$$(mktemp -d); dir2=$$(mktemp -d); \
	echo "build 1 in $$dir1 (fresh GOCACHE+GOPATH)"; \
	GOCACHE=$$dir1/gocache GOPATH=$$dir1/gopath $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $$dir1/relayd ./cmd/relayd; \
	echo "build 2 in $$dir2 (fresh GOCACHE+GOPATH)"; \
	GOCACHE=$$dir2/gocache GOPATH=$$dir2/gopath $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $$dir2/relayd ./cmd/relayd; \
	cmp $$dir1/relayd $$dir2/relayd; \
	echo "reproducible build OK: $$(shasum -a 256 $$dir1/relayd | cut -d' ' -f1)"; \
	rm -rf $$dir1 $$dir2

.PHONY: modverify
modverify:
	$(GO) mod verify

.PHONY: vendor-check
vendor-check:
	$(GO) mod vendor
	git diff --exit-code -- vendor/ go.mod go.sum || (echo "vendor/ is not up to date with go.mod/go.sum; run 'go mod vendor' and commit the result" && exit 1)

.PHONY: ci
ci: lint vuln modverify vendor-check test-race coverage fuzz-short proto verify-repro sbom
