// Package tetragoncrd embeds the vendored Tetragon v1.8.0 TracingPolicy CRD
// using the embed directive below, so internal/policydoc can compile it
// into a JSON Schema at build time. See README.md in this directory for
// provenance and the SHA-256 `make verify-crd` checks in CI.
//
// This file exists only because embed patterns may not contain ".." path
// elements, so internal/policydoc (a different package) cannot embed this
// directory's file directly; wrapping it in its own tiny package is the
// standard way to vendor an embeddable data file outside the importing
// package's own directory tree.
package tetragoncrd

import _ "embed"

// TracingPoliciesCRD is the raw bytes of
// cilium.io_tracingpolicies.yaml as vendored from cilium/tetragon at tag
// v1.8.0 (see README.md for the exact commit and SHA-256).
//
//go:embed cilium.io_tracingpolicies.yaml
var TracingPoliciesCRD []byte
