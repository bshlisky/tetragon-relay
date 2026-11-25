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
	"bytes"
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
	provisionTPM := fs.Bool("provision-tpm", false, "provision the persistent SRK and the TPM NV counter index used for store rollback protection, then exit (run once, before the agent's first start)")
	tpmDevice := fs.String("tpm-device", "/dev/tpmrm0", "TPM resource manager device path (--provision-tpm only; architecture doc 8.6 -- never /dev/tpm0)")
	tpmOwnerAuthFile := fs.String("tpm-owner-auth-file", "", "root-only file containing the TPM owner hierarchy's authorization value (--provision-tpm only; omit if the host's TPM has no owner password set, the common case -- docs/decisions/0029-no-tpm-owner-authorization-at-runtime.md). relayd itself never reads this file or any owner authorization.")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *provisionTPM {
		if err := provisionTPMComponents(*tpmDevice, *tpmOwnerAuthFile); err != nil {
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

// provisionTPMComponents opens the TPM resource manager device and
// provisions (or validates already-correct) persistent SRK
// (tpm.ProvisionSRK) and NV counter index (tpm.ProvisionCounter) at
// tpm.DefaultCounterHandle (docs/decisions/0029-no-tpm-owner-
// authorization-at-runtime.md, superseding docs/prompts/step-05a.md C3).
// Run once, by this root-run command via the unit's ExecStartPre=+
// (packaging/systemd/tetragon-relay.service); relayd itself (unprivileged)
// never creates/persists the SRK or defines/undefines the counter index,
// only loads/reads/increments them (internal/tpm.OpenSRK,
// internal/tpm.OpenCounter) with no TPM owner-hierarchy authorization at
// all. Idempotent: running it again against already-correctly-provisioned
// objects is a no-op, so it is safe to run on every unit start, not just
// the first.
//
// ownerAuthFile is optional. If set, it names a root-only file whose
// exact contents (with at most one trailing newline stripped) are used as
// the TPM owner hierarchy's authorization value for this one provisioning
// run -- the operator procedure for a host whose TPM already has an owner
// password set by the site's provisioning standard (ADR 0029). If empty,
// provisioning uses an empty owner authorization, matching the common
// case of a TPM with no owner password. This value is read exactly once,
// here, and is never read by relayd.
func provisionTPMComponents(devicePath, ownerAuthFile string) error {
	ownerAuth, err := readOwnerAuthFile(ownerAuthFile)
	if err != nil {
		return err
	}
	dev, err := tpm.OpenDevice(devicePath)
	if err != nil {
		return fmt.Errorf("open TPM device %s: %w", devicePath, err)
	}
	defer func() { _ = dev.Close() }()
	if _, err := tpm.ProvisionSRK(dev, ownerAuth); err != nil {
		return fmt.Errorf("provision SRK: %w", err)
	}
	if err := tpm.ProvisionCounter(dev, tpm.DefaultCounterHandle, ownerAuth); err != nil {
		return fmt.Errorf("provision NV counter: %w", err)
	}
	return nil
}

// readOwnerAuthFile reads the TPM owner authorization value from path, or
// returns nil (empty authorization) if path is empty. A non-empty path
// that cannot be read is a hard error: provisioning never silently falls
// back to an empty owner authorization when the operator explicitly
// configured a file to read it from.
func readOwnerAuthFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is an explicit, operator-supplied flag, read once by this root-run provisioning command, never from untrusted input
	if err != nil {
		return nil, fmt.Errorf("read TPM owner auth file %s: %w", path, err)
	}
	return bytes.TrimSuffix(raw, []byte("\n")), nil
}

func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}
