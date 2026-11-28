//go:build linux

package main

import (
	"os"
	"slices"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/hostprobe"
)

func TestSplitNUL(t *testing.T) {
	if got := splitNUL([]byte("a\x00--b=1\x00\x00")); !slices.Equal(got, []string{"a", "--b=1"}) {
		t.Fatalf("%q", got)
	}
	if splitNUL(nil) != nil {
		t.Fatal("nil")
	}
}

// The test binary itself stands in for a "Tetragon" process.
func TestReadTetragonEnvCollection_FindsProcessByExe(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if v, src := readTetragonEnvCollection(exe); v == hostprobe.EnvCollectionUnknown {
		t.Fatalf("did not find this process: %s", src)
	}
	if v, _ := readTetragonEnvCollection("/nonexistent/tetragon"); v != hostprobe.EnvCollectionUnknown {
		t.Fatalf("found a nonexistent binary: %s", v)
	}
}
