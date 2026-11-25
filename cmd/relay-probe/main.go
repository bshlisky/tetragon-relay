// Command relay-probe implements step 3 prompt Part C: it must run as root
// (systemd ExecStartPre=+... before the agent starts; packaging/systemd/
// tetragon-relay.service) to gather host facts the unprivileged agent
// cannot read itself, and writes them atomically to
// hostprobe.HostFactsPath for internal/hostprobe to load. `relay-probe
// --report` prints the same facts as JSON to stdout instead of writing the
// file, for the RHEL 9 kernel capability matrix (docs/runbooks/
// capability-matrix.md).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/bshlisky/tetragon-relay/internal/hostprobe"
	"github.com/bshlisky/tetragon-relay/internal/tpm"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("relay-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	report := fs.Bool("report", false, "print host facts as JSON to stdout instead of writing the facts file")
	tetragonBinaryPath := fs.String("tetragon-binary", "/usr/local/bin/tetragon", "path to the Tetragon daemon binary to hash")
	factsPath := fs.String("facts-path", hostprobe.HostFactsPath, "where to write the host facts file (ignored with --report)")
	relayGroup := fs.String("relay-group", "tetragon-relay", "group that should own the facts file (ignored with --report)")
	provisionTPM := fs.Bool("provision-tpm", false, "provision the TPM NV counter index used for store rollback protection, then exit (requires owner authorization; run once, before the agent's first start)")
	tpmDevice := fs.String("tpm-device", "/dev/tpmrm0", "TPM resource manager device path (--provision-tpm only; architecture doc 8.6 -- never /dev/tpm0)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *provisionTPM {
		if err := provisionTPMCounter(*tpmDevice); err != nil {
			_, _ = fmt.Fprintf(stderr, "relay-probe: provision TPM: %v\n", err)
			return 1
		}
		return 0
	}

	facts, err := collect(*tetragonBinaryPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "relay-probe: %v\n", err)
		return 1
	}

	if *report {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(facts); err != nil {
			_, _ = fmt.Fprintf(stderr, "relay-probe: encode report: %v\n", err)
			return 1
		}
		return 0
	}

	gid, err := lookupGID(*relayGroup)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "relay-probe: resolve group %q: %v\n", *relayGroup, err)
		return 1
	}
	dir := filepath.Dir(*factsPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		_, _ = fmt.Fprintf(stderr, "relay-probe: create %s: %v\n", dir, err)
		return 1
	}
	if err := hostprobe.WriteAtomic(*factsPath, facts, 0, gid); err != nil {
		_, _ = fmt.Fprintf(stderr, "relay-probe: write %s: %v\n", *factsPath, err)
		return 1
	}
	return 0
}

// provisionTPMCounter opens the TPM resource manager device and
// provisions (or validates an already-correct) NV counter index at
// tpm.DefaultCounterHandle (docs/prompts/step-05a.md C3). Run once, by
// this root-run command via the unit's ExecStartPre=+
// (packaging/systemd/tetragon-relay.service); relayd itself (unprivileged)
// never defines or undefines this index, only reads and increments it
// (internal/tpm.OpenCounter). Idempotent: running it again against an
// already-correctly-provisioned index is a no-op, so it is safe to run on
// every unit start, not just the first.
func provisionTPMCounter(devicePath string) error {
	dev, err := tpm.OpenDevice(devicePath)
	if err != nil {
		return fmt.Errorf("open TPM device %s: %w", devicePath, err)
	}
	defer func() { _ = dev.Close() }()
	return tpm.ProvisionCounter(dev, tpm.DefaultCounterHandle)
}

func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}
