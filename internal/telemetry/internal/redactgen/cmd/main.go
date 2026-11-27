// Command redactgen writes internal/telemetry/redact_gen.go (go generate
// in internal/telemetry).
package main

import (
	"fmt"
	"os"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/internal/redactgen"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: redactgen <output.go>")
		os.Exit(2)
	}
	src, err := redactgen.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], src, 0o644); err != nil { //nolint:gosec // G306: a source file
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
