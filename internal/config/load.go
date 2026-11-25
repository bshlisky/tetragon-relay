package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/yamlharden"
)

// relayGroupName is the group relay.yaml must be owned by (architecture
// doc 8.5's filesystem table: "root:tetragon-relay, 0640"). Fixed, not
// configurable: the mechanism that verifies relay.yaml's own trust cannot
// itself be configured by relay.yaml.
const relayGroupName = "tetragon-relay"

// lookupGroupGID resolves a POSIX group name to a gid. A package variable
// (not a direct os/user call) purely so tests can inject a resolvable
// group without requiring the real "tetragon-relay" system group to exist
// on the machine running `go test` -- the same test-seam pattern
// internal/apply/persist.go and internal/hostprobe/write.go already use
// for otherwise-hard-to-control OS behavior. Production code never
// overrides this.
var lookupGroupGID = func(name string) (uint32, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(gid), nil
}

// checkFileSourceable implements Part B1: before relay.yaml's bytes are
// trusted at all, it must be a regular file (never a symlink), owned by
// root, group relayGroupName, with mode no more permissive than
// limits.MaxConfigFileMode.
func checkFileSourceable(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return fmt.Errorf("config: stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrConfigIsSymlink, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrConfigNotRegularFile, path)
	}
	if mode := fi.Mode().Perm(); mode&^os.FileMode(limits.MaxConfigFileMode) != 0 {
		return fmt.Errorf("%w: %s has mode %o", ErrConfigModeTooPermissive, path, mode)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// step-04b-review.md R4B-3's precedent (internal/store's
		// checkOwnerAndMode): fail closed rather than silently
		// downgrading to a mode-only check on a platform where
		// ownership cannot be verified at all.
		return fmt.Errorf("%w: fi.Sys() is %T, not *syscall.Stat_t", ErrConfigCannotVerifyOwnership, fi.Sys())
	}
	if uint32(st.Uid) != 0 { //nolint:unconvert // Uid's width differs across platforms
		return fmt.Errorf("%w: %s is owned by uid %d", ErrConfigNotOwnedByRoot, path, st.Uid)
	}
	wantGID, err := lookupGroupGID(relayGroupName)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfigGroupLookupFailed, err)
	}
	if uint32(st.Gid) != wantGID { //nolint:unconvert // Gid's width differs across platforms
		return fmt.Errorf("%w: %s has group gid %d, want %d (%s)", ErrConfigWrongGroup, path, st.Gid, wantGID, relayGroupName)
	}
	return nil
}

// readConfigFile reads path's bytes, bounded by limits.MaxConfigFileBytes
// (an oversized file is a typed error, never a silent truncation).
func readConfigFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the operator-configured --config flag (Part C), checked by checkFileSourceable immediately before this call, not attacker-controlled input
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	limited := io.LimitReader(f, limits.MaxConfigFileBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	if len(raw) > limits.MaxConfigFileBytes {
		return nil, fmt.Errorf("%w: %s", ErrConfigTooLarge, path)
	}
	return raw, nil
}

// Load reads, hardens, parses and validates relay.yaml at path (Part B).
// path is normally the --config flag's value (cmd/relayd, Part C).
func Load(path string) (*Config, error) {
	if err := checkFileSourceable(path); err != nil {
		return nil, err
	}
	raw, err := readConfigFile(path)
	if err != nil {
		return nil, err
	}
	return parse(raw)
}

// parse implements Part B2/B3 on already-read bytes raw: hardened-YAML
// ingestion (internal/yamlharden, shared with internal/policydoc),
// closed-schema strict decoding, and field validation/defaulting. Split
// out from Load so FuzzConfig (Part B5) and tests can exercise it without
// touching the filesystem or Part B1's ownership checks.
func parse(raw []byte) (*Config, error) {
	// internal/yamlharden.Parse applies the same hardening rules
	// internal/policydoc uses for policy YAML (anchors, aliases,
	// explicit tags, merge keys, bounded depth/node count/scalar size,
	// duplicate keys, YAML-1.1-ambiguous scalars, decoded control/
	// invisible characters). Its returned node is discarded: the typed
	// decode below re-parses raw independently via yaml.v3's
	// KnownFields(true), which neither internal/yamlharden nor
	// internal/policydoc's own canonical-JSON path needs for their own
	// purposes, so there is no existing single-pass API this package
	// could reuse without changing either of them.
	if _, err := yamlharden.Parse(raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var rc rawConfig
	if err := dec.Decode(&rc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	cfg, err := validateAndBuild(rc)
	if err != nil {
		return nil, err
	}
	cfg.digest = sha256.Sum256(raw)
	return cfg, nil
}
