//go:build testtools

// Command bundlesign-test is a TEST-ONLY tool for generating ECDSA P-384
// test keys, trust-root metadata, and signed policy-bundle envelopes. It is
// built only with the `testtools` build tag and is never part of a
// production release; see docs/decisions/0001-dependencies.md.
//
// It writes the committed test vectors under testdata/vectors/. Keys it
// generates are test-only, clearly labeled, and MUST NOT be used for
// anything but local verification tests.
//
// Usage: go run -tags testtools ./cmd/bundlesign-test -out testdata/vectors
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	out := flag.String("out", "testdata/vectors", "output directory for generated vectors")
	flag.Parse()

	if err := generateAll(*out); err != nil {
		fmt.Fprintln(os.Stderr, "bundlesign-test:", err)
		os.Exit(1)
	}
}
