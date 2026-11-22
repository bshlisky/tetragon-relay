// Command relayd is the on-host relay agent described in Section 8 of
// docs/security-architecture.md. It is the sole permitted caller of the
// local Tetragon gRPC socket and the only bridge between a host and the
// management plane.
//
// This is a placeholder entry point; the agent's responsibilities
// (identity/enrollment, control stream, bundle verification, apply/rollback,
// telemetry forwarding) have not been implemented yet.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "relayd: not yet implemented; see docs/security-architecture.md")
	os.Exit(1)
}
