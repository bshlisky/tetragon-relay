// Command relayd is the on-host relay agent described in architecture doc
// section 8. This step only builds the repository scaffold and the
// signature-verification core (internal/trust, internal/verify); relayd
// itself has no functionality yet beyond reporting its own version.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is set at build time via -ldflags "-X main.version=...". It
// defaults to "dev" for local builds.
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	fmt.Fprintln(os.Stderr, "relayd: not yet implemented beyond --version; see docs/architecture.md")
	os.Exit(1)
}
