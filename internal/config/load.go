package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"bytes"
	"crypto/sha256"

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

// statT extracts owning uid/gid from fi, failing closed (R5A-review's
// precedent, internal/store's checkOwnerAndMode) on a platform where
// fi.Sys() is not *syscall.Stat_t rather than silently downgrading to a
// mode-only check.
func statT(fi os.FileInfo) (*syscall.Stat_t, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%w: fi.Sys() is %T, not *syscall.Stat_t", ErrConfigCannotVerifyOwnership, fi.Sys())
	}
	return st, nil
}

// openConfigFile implements step-06a-review B6: relay.yaml is opened with
// O_NOFOLLOW (a symlink at path is refused by the open(2) call itself,
// returning ELOOP, never silently followed) before anything about it is
// trusted, and every check below (regular file, mode, owner, group) is
// performed with f.Stat() on the now-open file descriptor, not a second,
// separate Lstat/Stat of the path -- closing the check-then-open race a
// path-based check alone would leave (the file at path could be replaced
// between a passing Lstat and a later Open). An Lstat-based early check
// is deliberately NOT done first: the only authoritative check is the
// descriptor-based one below, so there is exactly one code path to keep
// correct, not two that must agree.
//
// Go's os.OpenFile already sets the close-on-exec flag on every file
// descriptor it opens (syscall.CloseOnExec, applied internally by the
// runtime's poll.FD on every platform this project targets); O_CLOEXEC is
// not passed explicitly in flags because doing so is redundant, not
// because it is skipped.
func openConfigFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: path is the operator-configured --config flag (Part C); O_NOFOLLOW below refuses a symlink at this exact path regardless of what it names
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		case errors.Is(err, syscall.ELOOP):
			return nil, fmt.Errorf("%w: %s", ErrConfigIsSymlink, path)
		default:
			return nil, fmt.Errorf("config: open %s: %w", path, err)
		}
	}
	if err := checkOpenedConfigFile(f, path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// checkOpenedConfigFile implements the regular-file/mode/owner/group
// checks of Part B1, against f (already open, O_NOFOLLOW) rather than
// path.
func checkOpenedConfigFile(f *os.File, path string) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("config: fstat %s: %w", path, err)
	}
	return validateConfigFileInfo(fi, path)
}

// validateConfigFileInfo is checkOpenedConfigFile's policy, factored out
// as a pure function of an os.FileInfo so it can be unit-tested against a
// synthetic FileInfo (fileInfoStub, in the test file) without needing a
// real root-owned or tetragon-relay-group-owned file: a non-root CI
// runner can exercise every branch, including the ones that would
// otherwise only be reachable by running as root (step-06a-review B6/B7
// follow-up: both ownership-relaxation gates this package applies tended
// to lose test coverage specifically on the branches only root could
// trigger end-to-end).
func validateConfigFileInfo(fi os.FileInfo, path string) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		// Unreachable in practice (O_NOFOLLOW already refused opening a
		// symlink at path), kept as a defensive invariant: f.Stat()
		// never reports ModeSymlink for an fd obtained via a successful
		// open(2), but if some future platform's semantics ever
		// differed, this still fails closed rather than trusting it.
		return fmt.Errorf("%w: %s", ErrConfigIsSymlink, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrConfigNotRegularFile, path)
	}
	if mode := fi.Mode().Perm(); mode&^os.FileMode(limits.MaxConfigFileMode) != 0 {
		return fmt.Errorf("%w: %s has mode %o", ErrConfigModeTooPermissive, path, mode)
	}
	st, err := statT(fi)
	if err != nil {
		return err
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

// checkParentDir implements step-06a-review B7: the directory containing
// relay.yaml must be owned by root, must not itself be (or be reached
// through, at its own final path component) a symlink, and must not be
// writable by group or other -- otherwise a non-root principal with write
// access to the directory could replace relay.yaml out from under
// openConfigFile's own O_NOFOLLOW check (which only protects against
// relay.yaml's own path component being a symlink, not against the
// directory holding it being attacker-writable). The directory is opened
// with O_DIRECTORY|O_NOFOLLOW (mirroring openConfigFile's own descriptor-
// based check, not a path-based Lstat) and checked via Fstat on that
// descriptor.
func checkParentDir(path string) error {
	dir := filepath.Dir(path)
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: dir is derived from the operator-configured --config flag (Part C)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("%w: %s", ErrConfigParentDirNotFound, dir)
		case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENOTDIR):
			return fmt.Errorf("%w: %s", ErrConfigParentDirIsSymlink, dir)
		default:
			return fmt.Errorf("config: open directory %s: %w", dir, err)
		}
	}
	defer func() { _ = d.Close() }()

	fi, err := d.Stat()
	if err != nil {
		return fmt.Errorf("config: fstat %s: %w", dir, err)
	}
	return validateParentDirInfo(fi, dir)
}

// validateParentDirInfo is checkParentDir's policy, factored out as a
// pure function of an os.FileInfo for the same unit-testability reason as
// validateConfigFileInfo above.
func validateParentDirInfo(fi os.FileInfo, dir string) error {
	if !fi.IsDir() {
		// Unreachable given O_DIRECTORY (the open itself would have
		// failed with ENOTDIR), kept as a defensive invariant.
		return fmt.Errorf("%w: %s", ErrConfigParentDirIsSymlink, dir)
	}
	if mode := fi.Mode().Perm(); mode&0o022 != 0 {
		return fmt.Errorf("%w: %s has mode %o (writable by group or other)", ErrConfigParentDirWritable, dir, mode)
	}
	st, err := statT(fi)
	if err != nil {
		return err
	}
	if uint32(st.Uid) != 0 { //nolint:unconvert // Uid's width differs across platforms
		return fmt.Errorf("%w: %s is owned by uid %d", ErrConfigParentDirNotOwnedByRoot, dir, st.Uid)
	}
	return nil
}

// readOpenedConfigFile reads f's bytes from the current offset (f is
// openConfigFile's already O_NOFOLLOW-opened, already fstat-checked
// descriptor -- not re-opened by path), bounded by
// limits.MaxConfigFileBytes (an oversized file is a typed error, never a
// silent truncation).
func readOpenedConfigFile(f *os.File, path string) ([]byte, error) {
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
	f, err := openConfigFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	if err := checkParentDir(path); err != nil {
		return nil, err
	}
	raw, err := readOpenedConfigFile(f, path)
	if err != nil {
		return nil, err
	}
	return parse(raw)
}

// parse implements Part B2/B3 on already-read bytes raw: hardened-YAML
// ingestion (internal/yamlharden, shared with internal/policydoc),
// closed-schema strict decoding, and field validation/defaulting. Split
// out from Load so FuzzConfig (Part B5) and tests can exercise it without
// touching the filesystem or Part B1/B6/B7's ownership checks.
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
