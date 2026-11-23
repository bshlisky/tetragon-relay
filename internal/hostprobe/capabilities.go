package hostprobe

import (
	"fmt"
	"os"

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

// Load implements step 3 prompt Part C4: reads path (HostFactsPath by
// default), decodes it with internal/strictjson (duplicate-key/depth
// hardening, consistent with every other on-disk/wire format this project
// parses), and fails closed — a *Capabilities whose every method reports
// no capability at all, never an error the caller could choose to ignore —
// on any of: the file is missing or unreadable, it does not parse, its
// SchemaVersion is not HostFactsSchemaVersion, or its BootID does not equal
// currentBootID (facts from a previous boot).
//
// Load never itself returns a non-nil error for these conditions: a
// relay-controlled host fact file being stale or absent is an expected
// operational state (e.g. agent started before relay-probe finished, or a
// reboot since the last probe run), not a programming error, and the
// correct response is exactly what fail-closed Capabilities already gives
// a caller — reject every enforcement bundle, keep monitoring. The bool
// return reports which path was taken, purely for logging/diagnostics.
func Load(path, currentBootID string) (*Capabilities, bool) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-configured (architecture doc 8.6), not attacker-controlled
	if err != nil {
		return failClosedCapabilities(), false
	}
	facts, err := Parse(data)
	if err != nil {
		return failClosedCapabilities(), false
	}
	if facts.SchemaVersion != HostFactsSchemaVersion {
		return failClosedCapabilities(), false
	}
	if currentBootID == "" || facts.BootID != currentBootID {
		return failClosedCapabilities(), false
	}
	return &Capabilities{facts: facts}, true
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
// UUID that changes every boot. Linux-only (the only platform this project
// targets); returns ("", err) if unreadable, which Load treats as a
// mismatch (fail closed) via the currentBootID == "" check.
func CurrentBootID() (string, error) {
	return currentBootID()
}
