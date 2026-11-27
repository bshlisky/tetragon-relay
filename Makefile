SHELL := /bin/bash
GO ?= go
GOBIN ?= $(shell $(GO) env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

MODULE := github.com/bshlisky/tetragon-relay
VERSION ?= $(shell git -C $(CURDIR) describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X 'main.version=$(VERSION)'

COVER_PKGS := ./internal/dsse/... ./internal/strictjson/... ./internal/trust/... ./internal/verify/... ./internal/policydoc/... ./internal/guard/...

.PHONY: all
all: ci

.PHONY: build
build:
	$(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/relayd ./cmd/relayd
	GOOS=linux $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/relay-probe ./cmd/relay-probe

.PHONY: test
test:
	$(GO) test -count=1 ./...

.PHONY: test-race
test-race:
	$(GO) test -race -count=1 -cover ./...

.PHONY: coverage
coverage:
	@fail=0; \
	for pkg in internal/dsse internal/strictjson internal/trust internal/verify internal/policydoc internal/guard internal/store; do \
		echo "== $$pkg =="; \
		$(GO) test -count=1 -covermode=count -coverprofile=/tmp/tetragon-relay-$$(basename $$pkg).out ./$$pkg/... >/dev/null; \
		line=$$($(GO) tool cover -func=/tmp/tetragon-relay-$$(basename $$pkg).out | tail -1); \
		echo "$$line"; \
		pct=$$(echo "$$line" | awk '{print $$NF}' | tr -d '%'); \
		awk -v p="$$pct" 'BEGIN { exit !(p+0 >= 95) }' || { echo "$$pkg coverage $$pct% is below the required 95%"; fail=1; }; \
	done; \
	exit $$fail

COVER90_PKGS := internal/tetra internal/apply internal/hostprobe internal/agent internal/identity internal/controlclient internal/config internal/audit internal/telemetry internal/spiffetls

.PHONY: coverage90
coverage90:
	@fail=0; \
	for pkg in $(COVER90_PKGS); do \
		if [ ! -d "$$pkg" ]; then continue; fi; \
		echo "== $$pkg (>=90% gate; step 3 prompt Part E5) =="; \
		$(GO) test -count=1 -covermode=count -coverprofile=/tmp/tetragon-relay-$$(basename $$pkg).out ./$$pkg/... >/dev/null; \
		line=$$($(GO) tool cover -func=/tmp/tetragon-relay-$$(basename $$pkg).out | tail -1); \
		echo "$$line"; \
		pct=$$(echo "$$line" | awk '{print $$NF}' | tr -d '%'); \
		awk -v p="$$pct" 'BEGIN { exit !(p+0 >= 90) }' || { echo "$$pkg coverage $$pct% is below the required 90%"; fail=1; }; \
	done; \
	exit $$fail

COVER_TPM_PKG := internal/tpm

# step-05a prompt D1/D4: internal/tpm's tests skip (not fail) without a
# real swtpm on PATH, so neither of these is part of the main `ci` target
# -- only the dedicated `tpm` CI job (which installs swtpm) runs them,
# where they genuinely exercise every test against a real TPM 2.0
# implementation, not report a false-low coverage number from mostly
# skipped tests.
.PHONY: tpm-test
tpm-test:
	$(GO) test -race -count=1 -v ./$(COVER_TPM_PKG)/...

.PHONY: coverage-tpm
coverage-tpm:
	@echo "== $(COVER_TPM_PKG) (>=90% gate; step-05a prompt D4) =="; \
	$(GO) test -count=1 -covermode=count -coverprofile=/tmp/tetragon-relay-tpm.out ./$(COVER_TPM_PKG)/... >/dev/null; \
	line=$$($(GO) tool cover -func=/tmp/tetragon-relay-tpm.out | tail -1); \
	echo "$$line"; \
	pct=$$(echo "$$line" | awk '{print $$NF}' | tr -d '%'); \
	awk -v p="$$pct" 'BEGIN { exit !(p+0 >= 90) }' || { echo "$(COVER_TPM_PKG) coverage $$pct% is below the required 90%"; exit 1; }

.PHONY: bench-gate
# Step 7b P1/P3: pipeline benchmark, per-stage breakdown, profiles, CPU gate.
bench-gate:
	scripts/bench-gate.sh bench-out

.PHONY: fuzz-short
fuzz-short:
	$(GO) test -run=NONE -fuzz=FuzzStrictJSON -fuzztime=60s ./internal/strictjson/...
	$(GO) test -run=NONE -fuzz=FuzzVerifyEnvelope -fuzztime=60s ./internal/verify/...
	$(GO) test -run=NONE -fuzz=FuzzRootUpdate -fuzztime=60s ./internal/trust/...
	$(GO) test -run=NONE -fuzz=FuzzRootV2 -fuzztime=60s ./internal/trust/...
	$(GO) test -run=NONE -fuzz=FuzzPolicyParse -fuzztime=60s ./internal/policydoc/...
	$(GO) test -run=NONE -fuzz=FuzzGuard -fuzztime=60s ./internal/guard/...
	$(GO) test -run=NONE -fuzz=FuzzStoreIndex -fuzztime=60s ./internal/store/...
	$(GO) test -run=NONE -fuzz=FuzzConfig -fuzztime=60s ./internal/config/...
	$(GO) test -run=NONE -fuzz=FuzzBatchHeader -fuzztime=60s ./internal/telemetry/batch
	$(GO) test -run=NONE -fuzz=FuzzSpoolFile -fuzztime=60s ./internal/telemetry
	$(GO) test -run=NONE -fuzz=FuzzChainVerify -fuzztime=60s ./internal/telemetry/chainverify
	$(GO) test -run=NONE -fuzz=FuzzRedactEquivalence -fuzztime=60s ./internal/telemetry
	$(GO) test -run=NONE -fuzz=FuzzArgvPrefilter -fuzztime=60s ./internal/telemetry

.PHONY: lint
lint:
	gofmt -l $$(find . -name '*.go' -not -path './vendor/*' -not -path './api/*' -not -path './third_party/tetragon/v1.8.0/api/*') | tee /tmp/gofmt-out; test ! -s /tmp/gofmt-out
	goimports -l $$(find . -name '*.go' -not -path './vendor/*' -not -path './api/*' -not -path './third_party/tetragon/v1.8.0/api/*') | tee /tmp/goimports-out; test ! -s /tmp/goimports-out
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
# Advanced to the commit landing ADR 0037 (STATUS_UNSPECIFIED = 0, step 7a A1).
PROTO_BASELINE := 6bc2b62c8aa31685b61e351bc42c4bb33f33367e

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

CRD_PATH := third_party/tetragon/v1.8.0/cilium.io_tracingpolicies.yaml
CRD_SHA256 := d99daa68c99faeab6a32ea843ab9a381ea2f63666b26e265bf048ac0ab617869

.PHONY: verify-crd
verify-crd:
	@got=$$(shasum -a 256 $(CRD_PATH) | cut -d' ' -f1); \
	if [ "$$got" != "$(CRD_SHA256)" ]; then \
		echo "$(CRD_PATH) sha256 mismatch: got $$got, want $(CRD_SHA256)"; \
		exit 1; \
	fi; \
	echo "verify-crd OK: $$got"

TETRAGON_API_DIR := third_party/tetragon/v1.8.0/api/v1/tetragon
TETRAGON_API_MANIFEST := $(TETRAGON_API_DIR)/MANIFEST.sha256

.PHONY: verify-tetragon-api
verify-tetragon-api:
	@cd $(TETRAGON_API_DIR) && shasum -a 256 -c MANIFEST.sha256 --status \
		&& echo "verify-tetragon-api OK" \
		|| (echo "$(TETRAGON_API_DIR) does not match MANIFEST.sha256 (re-vendoring or tampering); see README.md" && exit 1)

# step-06a-e3-prompt.md C1: a production relayd (no build tags) must
# never contain any testca/testenroll symbol in its symbol table --
# "never in production relayd" checked at the binary level, not just by
# code review of which files a build tag excludes. `go version -m`
# first confirms the binary itself was built with no -tags at all (a
# GOFLAGS=-tags=... leak would show up there as a "build -tags=..."
# line); `go tool nm` then confirms the actual symbol table, which is
# the authoritative check (a symbol could in principle survive even a
# tagless build if some future refactor moved test-only code out from
# behind its build tag).
.PHONY: verify-no-test-symbols
verify-no-test-symbols:
	@set -e; \
	bin=$$(mktemp); \
	GOOS=linux $(GO) build -o $$bin ./cmd/relayd; \
	echo "== go version -m (confirming no build tags) =="; \
	$(GO) version -m $$bin | grep -E '^\s*build\s' || true; \
	if $(GO) version -m $$bin | grep -qE '^\s*build\s+-tags='; then \
		echo "production relayd was built with explicit -tags; verify-no-test-symbols requires a tagless build" >&2; \
		rm -f $$bin; exit 1; \
	fi; \
	echo "== go tool nm (symbol table) =="; \
	if $(GO) tool nm $$bin 2>/dev/null | grep -iE 'testca|testenroll|TestCA|NewTestEnroller'; then \
		echo "production relayd's symbol table contains a testca/testenroll symbol (C1 violation)" >&2; \
		rm -f $$bin; exit 1; \
	fi; \
	echo "verify-no-test-symbols OK: no testca/testenroll/TestCA/NewTestEnroller symbol in a tagless relayd build"; \
	rm -f $$bin

.PHONY: ci
ci: lint vuln modverify vendor-check verify-crd verify-tetragon-api verify-no-test-symbols test-race coverage coverage90 fuzz-short proto breaking verify-repro sbom
