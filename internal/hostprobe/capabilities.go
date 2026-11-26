package hostprobe

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"

	"github.com/bshlisky/tetragon-relay/internal/guard"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// Capabilities implements guard.HostCapabilities from a successfully
// loaded, fresh HostFacts. It is never constructed directly by a caller
// with a stale/invalid file in hand: Load returns a failClosed
// Capabilities instead in every such case, so there is exactly one
// well-tested path to "everything is false" (step 3 prompt Part C4).
type Capabilities struct {
	facts      *HostFacts
	failClosed bool
}

var _ guard.HostCapabilities = (*Capabilities)(nil)

// KprobeOverride implements guard.HostCapabilities.
func (c *Capabilities) KprobeOverride() bool {
	if c.failClosed {
		return false
	}
	return c.facts.KprobeOverride
}

// LSMBPF implements guard.HostCapabilities.
func (c *Capabilities) LSMBPF() bool {
	if c.failClosed {
		return false
	}
	return c.facts.LSMBPF
}

// UsrmergeOK reports whether Part C2's usrmerge invariant held at probe
// time. Not part of guard.HostCapabilities (it gates whether enforcement
// bundles may be applied at all, a step 3 Part D concern, not a
// per-guardrail capability), but exposed here since it comes from the same
// fact source and the same freshness/validity rules.
func (c *Capabilities) UsrmergeOK() bool {
	if c.failClosed {
		return false
	}
	return c.facts.UsrmergeOK
}

// Facts returns the underlying HostFacts if this Capabilities is not fail
// closed, and (nil, false) otherwise. Callers that need more than the
// guard.HostCapabilities/UsrmergeOK surface (e.g. an operator-facing
// status report) can use this; internal/guard and internal/apply's core
// decisions never need to.
func (c *Capabilities) Facts() (*HostFacts, bool) {
	if c.failClosed {
		return nil, false
	}
	return c.facts, true
}

// failClosedCapabilities is the single construction path for "treat the
// host as having no enforcement capability at all" (step 3 prompt Part
// C4), used by every error branch in Load.
func failClosedCapabilities() *Capabilities {
	return &Capabilities{failClosed: true}
}

// Typed reasons Load fails closed. Every one leaves the caller with
// fail-closed Capabilities; the error says why, for the audit record.
var (
	ErrHostFactsUnreadable  = errors.New("hostprobe: host facts file missing or unreadable")
	ErrHostFactsNotRegular  = errors.New("hostprobe: host facts file is not a regular file")
	ErrHostFactsNotTmpfs    = errors.New("hostprobe: host facts file is not on tmpfs, so it cannot be shown to be from this boot")
	ErrHostFactsOwner       = errors.New("hostprobe: host facts file is not owned by root")
	ErrHostFactsMode        = errors.New("hostprobe: host facts file mode is not 0640")
	ErrHostFactsMalformed   = errors.New("hostprobe: host facts file does not parse")
	ErrHostFactsSchema      = errors.New("hostprobe: host facts schema version unsupported")
	ErrHostFactsNoBootID    = errors.New("hostprobe: host facts carry no boot_id")
	ErrHostFactsUnsupported = errors.New("hostprobe: host facts freshness can only be established on linux")
)

// HostFactsMode is the exact permission set cmd/relay-probe writes the
// file with (WriteAtomic) and Load requires.
const HostFactsMode fs.FileMode = 0o640

// fileInfo is what Load's freshness rule needs to know about the opened
// file, gathered from the open descriptor (never a second path lookup).
type fileInfo struct {
	regular bool
	uid     uint32
	perm    fs.FileMode
	onTmpfs bool
}

// statOpenFile is platformStatOpenFile, a variable only so tests can
// exercise every branch of the freshness rule without root or tmpfs.
var statOpenFile = platformStatOpenFile

// Load implements step 3 prompt Part C4 under the freshness rule of
// ADR 0034 (docs/reviews/step-06a-e3-decisions.md D3), which replaced the
// boot_id comparison: relayd runs with ProcSubset=pid and cannot read
// /proc/sys/kernel/random/boot_id (E3 run 45858158620). The file must be
// a regular file (opened with O_NOFOLLOW) on a tmpfs filesystem (statfs
// type TMPFS_MAGIC), owned by root, with mode exactly 0640. /run is a
// tmpfs cleared every boot, and only the root ExecStartPre relay-probe
// can create a root-owned file there, so such a file was written this
// boot by relay-probe. It must then parse (internal/strictjson), carry
// SchemaVersion == HostFactsSchemaVersion and a non-empty BootID, which
// relayd uses as the current boot_id (Hello, telemetry).
//
// Load always returns non-nil Capabilities. On any failure they are
// fail closed (every method reports no capability) and the error, one of
// the ErrHostFacts* values (wrapped), says why. A stale or absent file is
// an expected operational state (agent started before relay-probe ran,
// or a probe failure), and the correct response is exactly what
// fail-closed Capabilities give: reject every enforcement bundle, keep
// monitoring.
func Load(path string) (*Capabilities, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // path is operator-configured (architecture doc 8.6), not attacker-controlled
	if err != nil {
		return failClosedCapabilities(), fmt.Errorf("%w: %w", ErrHostFactsUnreadable, err)
	}
	defer func() { _ = f.Close() }()

	info, err := statOpenFile(f)
	if err != nil {
		return failClosedCapabilities(), err
	}
	switch {
	case !info.regular:
		return failClosedCapabilities(), ErrHostFactsNotRegular
	case !info.onTmpfs:
		return failClosedCapabilities(), ErrHostFactsNotTmpfs
	case info.uid != 0:
		return failClosedCapabilities(), fmt.Errorf("%w (uid %d)", ErrHostFactsOwner, info.uid)
	case info.perm != HostFactsMode:
		return failClosedCapabilities(), fmt.Errorf("%w (%#o)", ErrHostFactsMode, info.perm)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return failClosedCapabilities(), fmt.Errorf("%w: %w", ErrHostFactsUnreadable, err)
	}
	facts, err := Parse(data)
	if err != nil {
		return failClosedCapabilities(), fmt.Errorf("%w: %w", ErrHostFactsMalformed, err)
	}
	if facts.SchemaVersion != HostFactsSchemaVersion {
		return failClosedCapabilities(), fmt.Errorf("%w (%d)", ErrHostFactsSchema, facts.SchemaVersion)
	}
	if facts.BootID == "" {
		return failClosedCapabilities(), ErrHostFactsNoBootID
	}
	return &Capabilities{facts: facts}, nil
}

// Parse decodes raw host-facts JSON (step 3 prompt Part E6's
// FuzzHostFacts target). Exported so cmd/relay-probe's own
// --report self-check and tests can decode without going through Load's
// freshness gate.
func Parse(data []byte) (*HostFacts, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("hostprobe: empty host facts file")
	}
	var f HostFacts
	if err := strictjson.DecodeStrict(data, limits.MaxJSONDepth, &f); err != nil {
		return nil, fmt.Errorf("hostprobe: decode host facts: %w", err)
	}
	return &f, nil
}

// CurrentBootID reads /proc/sys/kernel/random/boot_id, the kernel-assigned
// UUID that changes every boot. Linux-only. Used only by cmd/relay-probe
// (root, outside relayd's sandbox) to record BootID in the host facts;
// relayd itself never calls it (ADR 0034: under ProcSubset=pid the path
// does not exist), and takes the boot_id from Load's facts instead.
func CurrentBootID() (string, error) {
	return currentBootID()
}
