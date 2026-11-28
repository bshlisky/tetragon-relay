package apply

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

// Freshness sentinel (step-07b-decisions-3.md F0.1; ADR 0042).
//
// The health window treats "no admin-path event" as evidence of health
// only while the observation path is proven current. The proof is a
// sentinel: relayd itself performs one harmless, hooked operation (it
// opens <Dir>/<nonce>), the relay-sentinel policy reports it with Post
// only, and the event carries the path and so the nonce. A sentinel that
// arrives on the window's own stream proves Tetragon's pipeline has caught
// up to the moment it was fired.
//
// The policy is relay-managed (loaded in RelayDomain, re-asserted by
// Reconcile and before every health window) but is NOT part of the LKG
// set, the persisted tp.d directory, or loaded_digest: its name,
// "relay-sentinel-<8 hex>", never matches loadedNamePattern, so
// isRelayManaged (Digest, existingManaged, Apply's removals) ignores it.

// SentinelPolicyPrefix starts every relay-sentinel policy's loaded name.
// The 8 hex digits after it are the first 8 of sha256 over the policy's
// content without its name, so a policy built for another binary or
// directory has a different name and is replaced, not mistaken for ours.
const SentinelPolicyPrefix = "relay-sentinel-"

// DefaultSentinelDir is the production sentinel directory. It sits inside
// the unit's ReadWritePaths=/var/lib/tetragon-relay, so no unit change.
const DefaultSentinelDir = "/var/lib/tetragon-relay/sentinel"

// Sentinel is the health window's freshness probe. FileSentinel is the
// production implementation; tests substitute fakes that inject the
// matching event into a fake stream.
type Sentinel interface {
	// PolicyName is the loaded name of the sentinel policy; the window's
	// GetEvents subscription includes it.
	PolicyName() string
	// PolicyJSON is the policy document (JSON, which is valid YAML) to
	// load under PolicyName.
	PolicyJSON() []byte
	// Fire performs the hooked operation, tagged with nonce.
	Fire(nonce string) error
	// Nonce reports the nonce an event carries, if it is one of this
	// sentinel's events.
	Nonce(ev tetra.Event) (string, bool)
}

// FileSentinel hooks security_file_open for one binary (relayd's own) and
// one directory prefix.
type FileSentinel struct {
	dir    string // absolute, cleaned, no trailing slash
	binary string // absolute
	name   string
	doc    []byte
}

// validSentinelPath: both paths go into a document built with
// encoding/json (no YAML templating), so they cannot inject structure;
// they must still be absolute, clean and free of control characters, so a
// bad value fails here rather than in Tetragon.
func validSentinelPath(p string) bool {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || len(p) > 255 {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// NewFileSentinel returns the sentinel for binary (relayd's own
// executable, as Tetragon reports it in process.binary) and dir.
func NewFileSentinel(binary, dir string) (*FileSentinel, error) {
	if !validSentinelPath(binary) {
		return nil, fmt.Errorf("apply: sentinel binary %q must be an absolute, clean path", binary)
	}
	if !validSentinelPath(dir) || dir == "/" {
		return nil, fmt.Errorf("apply: sentinel dir %q must be an absolute, clean path", dir)
	}
	s := &FileSentinel{dir: dir, binary: binary}
	content, err := s.document("")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	s.name = SentinelPolicyPrefix + hex.EncodeToString(sum[:])[:8]
	if s.doc, err = s.document(s.name); err != nil {
		return nil, err
	}
	return s, nil
}

// document builds the TracingPolicy. Tetragon v1.8.0, verified on the real
// binary by TestIntegration_SentinelArrives: a kprobe on
// security_file_open with the file argument, scoped by matchBinaries to
// relayd and by a path Prefix to the sentinel directory. No matchActions:
// the default action is Post, so the policy never enforces anything.
func (s *FileSentinel) document(name string) ([]byte, error) {
	type selector struct {
		MatchBinaries []map[string]any `json:"matchBinaries"`
		MatchArgs     []map[string]any `json:"matchArgs"`
	}
	doc := map[string]any{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{
			"kprobes": []any{map[string]any{
				"call":    "security_file_open",
				"syscall": false,
				"args":    []any{map[string]any{"index": 0, "type": "file"}},
				"selectors": []selector{{
					MatchBinaries: []map[string]any{{"operator": "In", "values": []string{s.binary}}},
					MatchArgs:     []map[string]any{{"index": 0, "operator": "Prefix", "values": []string{s.dir + "/"}}},
				}},
			}},
		},
	}
	return json.Marshal(doc)
}

// PolicyName implements Sentinel.
func (s *FileSentinel) PolicyName() string { return s.name }

// PolicyJSON implements Sentinel.
func (s *FileSentinel) PolicyJSON() []byte { return append([]byte(nil), s.doc...) }

// Fire implements Sentinel: create <dir>/<nonce> exclusively (the open is
// the hooked operation), then close and remove it. The directory is
// created 0700 if missing.
func (s *FileSentinel) Fire(nonce string) error {
	if !validNonce(nonce) {
		return fmt.Errorf("apply: invalid sentinel nonce")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("apply: sentinel dir: %w", err)
	}
	p := filepath.Join(s.dir, nonce)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: fixed directory plus a hex nonce
	if err != nil {
		return fmt.Errorf("apply: sentinel open: %w", err)
	}
	cerr := f.Close()
	rerr := os.Remove(p)
	return errors.Join(cerr, rerr)
}

// Nonce implements Sentinel.
func (s *FileSentinel) Nonce(ev tetra.Event) (string, bool) {
	k := ev.Kprobe
	if k == nil || k.GetPolicyName() != s.name {
		return "", false
	}
	prefix := s.dir + "/"
	for _, a := range k.GetArgs() {
		p := a.GetFileArg().GetPath()
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		n := p[len(prefix):]
		if validNonce(n) {
			return n, true
		}
	}
	return "", false
}

// newNonce returns 16 random bytes, hex-encoded.
func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func validNonce(n string) bool {
	if len(n) != 32 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isSentinelPolicy reports whether a loaded policy is a relay-sentinel
// policy (ours or a stale one) in this engine's domain.
func isSentinelPolicy(name, domain, relayDomain string) bool {
	return domain == relayDomain && strings.HasPrefix(name, SentinelPolicyPrefix)
}

// EnsureSentinel loads this engine's sentinel policy if it is not loaded
// and removes any other relay-sentinel policy in its domain (one built for
// another binary path or directory). It never touches any other policy.
// With no sentinel configured it returns ErrNoSentinel: the health window
// cannot pass without one.
func (e *Engine) EnsureSentinel(ctx context.Context) error {
	s := e.cfg.Sentinel
	if s == nil {
		return ErrNoSentinel
	}
	statuses, err := e.client.ListTracingPolicies(ctx, e.cfg.domain())
	if err != nil {
		return fmt.Errorf("apply: sentinel: list: %w", err)
	}
	present := false
	var stale []string
	for _, st := range statuses {
		if !isSentinelPolicy(st.Name, st.Domain, e.cfg.domain()) {
			continue
		}
		if st.Name == s.PolicyName() {
			present = true
			continue
		}
		stale = append(stale, st.Name)
	}
	if !present {
		if err := e.client.AddTracingPolicy(ctx, string(s.PolicyJSON()), e.cfg.domain()); err != nil {
			return fmt.Errorf("apply: sentinel: add %s: %w", s.PolicyName(), err)
		}
		e.audit("sentinel_loaded", s.PolicyName(), nil, s.PolicyName())
	}
	for _, n := range stale {
		if err := e.client.DeleteTracingPolicy(ctx, n, e.cfg.domain()); err != nil {
			e.audit("sentinel_stale_delete_failed", err.Error(), err, n)
		}
	}
	return nil
}

// NewSelfSentinel returns the FileSentinel for the running executable
// (relayd in production; the test binary in integration tests) and dir.
// The executable path is /proc/self/exe resolved through symlinks, which is
// what Tetragon reports as process.binary for the process.
func NewSelfSentinel(dir string) (*FileSentinel, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("apply: sentinel: executable path: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	return NewFileSentinel(exe, dir)
}
