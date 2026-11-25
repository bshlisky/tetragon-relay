package agent_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/guard"
	"github.com/bshlisky/tetragon-relay/internal/policydoc"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/trust"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// This file tests ADR 0025 (step-04b-review.md R4B-2): the LKG is
// persisted as the raw signed envelope and re-verified at every startup
// against the exact trust-root version that verified it.

func realLKGPolicies(t *testing.T, bundle *verify.Bundle) apply.LKGSet {
	t.Helper()
	set, err := apply.ResolveLKGSet(bundle, apply.RealPolicyParser{})
	if err != nil {
		t.Fatalf("ResolveLKGSet: %v", err)
	}
	return set
}

// buildAndPersistLKG builds a real root + a real, signed bundle envelope
// for scope/mode, verifies it exactly as internal/verify.Verify would
// (so result.RawEnvelope/result.RootVersion/result.Bundle are genuine),
// and persists the corresponding LKGSet to st under domain. Returns the
// root envelope bytes/keys and the result for further use (e.g. building
// a rotation on top of the same root keys).
func buildAndPersistLKG(t *testing.T, st *store.Store, domain, scope, mode string, now time.Time) (rootEnv []byte, rootKeys []*genKey, result *verify.Result) {
	t.Helper()
	rootEnv, rootKeys, _, _, result = buildAndPersistLKGFull(t, st, domain, scope, mode, now)
	return rootEnv, rootKeys, result
}

// buildAndPersistLKGFull is buildAndPersistLKG, additionally returning the
// targets key and parsed *trust.Root, for tests that need to sign further,
// deliberately-broken envelopes against the exact same trust anchor.
func buildAndPersistLKGFull(t *testing.T, st *store.Store, domain, scope, mode string, now time.Time) (rootEnv []byte, rootKeys []*genKey, targetsKey *genKey, root *trust.Root, result *verify.Result) {
	t.Helper()
	rootEnv, rootKeys, targetsKey = standardRootWithTargetsKey(t, 1, now.Add(365*24*time.Hour))
	root, err := trust.LoadInitialRoot(rootEnv)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	if err := st.PersistTrustRoot(rootEnv, root.Version); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}

	envelope := buildBundleEnvelope(t, targetsKey, scope, mode, 1, now, []bundlePolicySpec{
		{name: "p1", version: 1, yaml: minimalPolicyYAML("p1")},
	})
	tv, err := root.TargetsVerifier(now)
	if err != nil {
		t.Fatalf("TargetsVerifier: %v", err)
	}
	res := verify.Verify(verify.Input{
		Envelope:        envelope,
		Now:             now,
		HostUUID:        "11111111-1111-4111-8111-111111111111",
		AllowedScopes:   []string{scope},
		TetragonVersion: "1.8.0",
		Trust:           tv,
		RootVersion:     root.Version,
		Epochs:          fakeEpochSource{},
		PolicyParser:    realLKGPolicyParser{},
		Guardrails:      allowAllGuardrailsFake{},
	})
	if res.Code != verify.CodeAccept {
		t.Fatalf("Verify = %v (%s), want CodeAccept", res.Code, res.Reason)
	}

	lkg := realLKGPolicies(t, res.Bundle)
	lkg.RawEnvelope = res.RawEnvelope
	lkg.RootVersion = res.RootVersion
	if err := st.Put(domain, lkg); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return rootEnv, rootKeys, targetsKey, root, &res
}

type fakeEpochSource struct{}

func (fakeEpochSource) Current(string) (uint64, error) { return 0, nil }

// realLKGPolicyParser delegates to the real internal/policydoc.Parse, so
// verify.Verify's own schema validation genuinely runs (matching
// internal/verify's own test convention), for verify.Input.PolicyParser.
type realLKGPolicyParser struct{}

func (realLKGPolicyParser) Parse(name, yamlDoc string) (*policydoc.Doc, error) {
	return policydoc.Parse(name, yamlDoc)
}

type allowAllGuardrailsFake struct{}

func (allowAllGuardrailsFake) Check(guard.GuardContext, []*policydoc.Doc) error { return nil }

func TestStartup_ReverifyLKG_HappyPathSurvivesRestart(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-reverify-test-key-0123456")}
	counter := store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	buildAndPersistLKG(t, st, apply.RelayDomain, "prod-db", "enforce", now)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := agent.Config{
		StoreDir: dir,
		Sealer:   sealer,
		Counter:  counter,
		Auditor:  &agent.FakeAuditor{},
	}
	res, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Startup: %v (LKG re-verification should pass for an untampered record)", err)
	}
	defer func() { _ = res.Store.Close() }()
}

func TestStartup_ReverifyLKG_TamperedEnvelopeWithMatchingHMACIsDetected(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-reverify-test-key-0123456")}
	counter := store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, _, result := buildAndPersistLKG(t, st, apply.RelayDomain, "prod-db", "enforce", now)

	// Simulate a compromised HMAC key: an attacker (or this test, in its
	// place) can recompute a VALID index HMAC over altered content using
	// the exact same Put() a legitimate write uses -- internal/store has
	// no way to tell this content was never actually verify.Verify'd.
	// Flipping one byte of the raw envelope must still be caught by
	// re-verification at the NEXT startup, independent of the store's
	// own (now-complicit) HMAC.
	tampered := append([]byte(nil), result.RawEnvelope...)
	tampered[len(tampered)/2] ^= 0xFF
	lkg := realLKGPolicies(t, result.Bundle)
	lkg.RawEnvelope = tampered
	lkg.RootVersion = result.RootVersion
	if err := st.Put(apply.RelayDomain, lkg); err != nil {
		t.Fatalf("Put (tampered): %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := agent.Config{
		StoreDir: dir,
		Sealer:   sealer,
		Counter:  counter,
		Auditor:  &agent.FakeAuditor{},
	}
	if _, err := agent.Startup(cfg, now.Add(time.Hour)); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want store.ErrTampered", err)
	}
}

// TestStartup_ReverifyLKG_NoRawEnvelopeIsTampered is the regression test
// for docs/reviews/step-04c-review.md R4C-1: an LKG entry with a valid
// store-index HMAC but no raw envelope recorded must be ErrTampered, not
// silently trusted. There is no genuine "pre-R4B-2 record" case this
// could legitimately represent (internal/store's LKG schema was
// introduced in step 4b and has never shipped without this check).
func TestStartup_ReverifyLKG_NoRawEnvelopeIsTampered(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-reverify-test-key-0123456")}
	counter := store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rootEnv, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	if err := st.PersistTrustRoot(rootEnv, 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	// Simulates an attacker who forged a valid store index HMAC and
	// rewrote the LKG blob with altered policies, omitting raw_envelope
	// entirely to try to dodge re-verification.
	if err := st.Put(apply.RelayDomain, apply.LKGSet{Mode: "enforce"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := agent.Config{StoreDir: dir, Sealer: sealer, Counter: counter, Auditor: &agent.FakeAuditor{}}
	if _, err := agent.Startup(cfg, now.Add(time.Hour)); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want store.ErrTampered (missing raw envelope must fail closed)", err)
	}
}

// TestStartup_ReverifyLKG_ZeroRootVersionIsTampered covers the other half
// of R4C-1: a RawEnvelope present but RootVersion == 0 (never a value
// trust.LoadInitialRoot/Update ever produces -- version must be >= 1) is
// also tamper, not treated as "nothing to check".
func TestStartup_ReverifyLKG_ZeroRootVersionIsTampered(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-reverify-test-key-0123456")}
	counter := store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rootEnv, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	if err := st.PersistTrustRoot(rootEnv, 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	if err := st.Put(apply.RelayDomain, apply.LKGSet{Mode: "enforce", RawEnvelope: []byte("present-but-root-version-zero")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := agent.Config{StoreDir: dir, Sealer: sealer, Counter: counter, Auditor: &agent.FakeAuditor{}}
	if _, err := agent.Startup(cfg, now.Add(time.Hour)); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want store.ErrTampered (RootVersion 0 must fail closed)", err)
	}
}

func TestStartup_ReverifyLKG_RootVersionNotRetainedIsTampered(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-reverify-test-key-0123456")}
	counter := store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rootEnv, _ := standardRoot(t, 1, now.Add(365*24*time.Hour))
	if err := st.PersistTrustRoot(rootEnv, 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	// RootVersion 99 was never persisted at all.
	if err := st.Put(apply.RelayDomain, apply.LKGSet{Mode: "enforce", RawEnvelope: []byte("irrelevant"), RootVersion: 99}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := agent.Config{StoreDir: dir, Sealer: sealer, Counter: counter, Auditor: &agent.FakeAuditor{}}
	if _, err := agent.Startup(cfg, now.Add(time.Hour)); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want store.ErrTampered", err)
	}
}

func TestStartup_ReverifyLKG_CorruptHistoricalRootFailsToParse(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-reverify-test-key-0123456")}
	counter := store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// store.PersistTrustRoot itself does not parse/validate raw bytes
	// (internal/store has no internal/trust dependency); persist
	// genuinely unparsable "root" bytes directly to exercise
	// reverifyDomainLKG's own parse-failure branch.
	if err := st.PersistTrustRoot([]byte("not a real root envelope"), 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	if err := st.Put(apply.RelayDomain, apply.LKGSet{Mode: "enforce", RawEnvelope: []byte("irrelevant"), RootVersion: 1}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := agent.Config{StoreDir: dir, Sealer: sealer, Counter: counter, Auditor: &agent.FakeAuditor{}}
	if _, err := agent.Startup(cfg, now.Add(time.Hour)); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want store.ErrTampered", err)
	}
}

// buildExpiredRootDomain sets up a store at a fresh directory whose
// persisted root expires 2 hours after now, with a real signed LKG for
// "prod-db" verified under it. Returns the store's directory, sealer and
// counter (store is closed before return) plus the raw envelope bytes
// actually persisted, so callers can optionally tamper with them before
// re-persisting (R4C-2's tampered-under-expired-root regression test).
func buildExpiredRootDomain(t *testing.T, now time.Time) (dir string, sealer store.KeySealer, counter store.MonotonicCounter, rawEnvelope []byte) {
	t.Helper()
	dir = t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer = &store.FakeKeySealer{Key: []byte("agent-reverify-test-key-0123456")}
	counter = store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	shortRootEnv, _, targetsKey := standardRootWithTargetsKey(t, 1, now.Add(2*time.Hour))
	root, err := trust.LoadInitialRoot(shortRootEnv)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	if err := st.PersistTrustRoot(shortRootEnv, root.Version); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	envelope := buildBundleEnvelope(t, targetsKey, "prod-db", "enforce", 1, now, []bundlePolicySpec{
		{name: "p1", version: 1, yaml: minimalPolicyYAML("p1")},
	})
	tv, err := root.TargetsVerifier(now)
	if err != nil {
		t.Fatalf("TargetsVerifier: %v", err)
	}
	res := verify.Verify(verify.Input{
		Envelope: envelope, Now: now, HostUUID: "11111111-1111-4111-8111-111111111111",
		AllowedScopes: []string{"prod-db"}, TetragonVersion: "1.8.0", Trust: tv, RootVersion: root.Version,
		Epochs: fakeEpochSource{}, PolicyParser: realLKGPolicyParser{}, Guardrails: allowAllGuardrailsFake{},
	})
	if res.Code != verify.CodeAccept {
		t.Fatalf("Verify = %v (%s)", res.Code, res.Reason)
	}
	lkg := realLKGPolicies(t, res.Bundle)
	lkg.RawEnvelope, lkg.RootVersion = res.RawEnvelope, res.RootVersion
	if err := st.Put(apply.RelayDomain, lkg); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return dir, sealer, counter, res.RawEnvelope
}

func TestStartup_ReverifyLKG_ExpiredHistoricalRootStillVerifiesAndSucceeds(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir, sealer, counter, _ := buildExpiredRootDomain(t, now)

	auditor := &agent.FakeAuditor{}
	cfg := agent.Config{StoreDir: dir, Sealer: sealer, Counter: counter, Auditor: auditor}
	// "now" here is 1 day later: the root (2h validity) has expired, but
	// the recorded envelope is genuine and must still verify (R4C-2:
	// expiry is audited as staleness, never a reason to skip the
	// signature check or to reject an otherwise-valid LKG).
	res, err := agent.Startup(cfg, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("Startup: %v, want success (expired root does not change a valid outcome)", err)
	}
	defer func() { _ = res.Store.Close() }()
	found := false
	for _, e := range auditor.Events {
		if e.Step == "lkg_reverify" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no lkg_reverify audit event for the expired-root staleness note; events = %+v", auditor.Events)
	}
}

// TestStartup_ReverifyLKG_ExpiredHistoricalRootStillDetectsTamper is the
// regression test for docs/reviews/step-04c-review.md R4C-2: before the
// fix, an expired historical root made reverifyDomainLKG skip the
// signature check entirely, so an attacker with a forged store index HMAC
// could point an altered LKG at any sufficiently old (expired) retained
// root version and bypass re-verification. ProvenanceVerifier must still
// catch the tamper even though the root has expired.
func TestStartup_ReverifyLKG_ExpiredHistoricalRootStillDetectsTamper(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir, sealer, counter, rawEnvelope := buildExpiredRootDomain(t, now)

	// Re-open the store, re-opening is necessary only to mutate the LKG
	// blob via the normal Put path (simulating a compromised-HMAC
	// attacker rewriting the LKG with an altered envelope, exactly as
	// TestStartup_ReverifyLKG_TamperedEnvelopeWithMatchingHMACIsDetected
	// does for the non-expired case).
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	set, ok := st.Get(apply.RelayDomain)
	if !ok {
		t.Fatalf("Get: domain not found")
	}
	tampered := append([]byte(nil), rawEnvelope...)
	tampered[len(tampered)/2] ^= 0xFF
	set.RawEnvelope = tampered
	if err := st.Put(apply.RelayDomain, set); err != nil {
		t.Fatalf("Put (tampered): %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := agent.Config{StoreDir: dir, Sealer: sealer, Counter: counter, Auditor: &agent.FakeAuditor{}}
	// "now" is 1 day later: the root has expired, but that must NOT
	// cause the tampered envelope to be accepted.
	if _, err := agent.Startup(cfg, now.Add(24*time.Hour)); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want store.ErrTampered (expired root must not bypass signature check)", err)
	}
}

func TestStartup_ReverifyLKG_CachedContentMismatchWithoutEnvelopeTamperIsDetected(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-reverify-test-key-0123456")}
	counter := store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, _, _, _, result := buildAndPersistLKGFull(t, st, apply.RelayDomain, "prod-db", "enforce", now)

	// The envelope itself is untouched and still verifies; only the
	// CACHED Mode is wrong (as if something edited the index-level cache
	// directly without ever re-signing or even touching RawEnvelope).
	lkg := realLKGPolicies(t, result.Bundle)
	lkg.Mode = "monitor" // wrong: the real envelope says "enforce"
	lkg.RawEnvelope = result.RawEnvelope
	lkg.RootVersion = result.RootVersion
	if err := st.Put(apply.RelayDomain, lkg); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := agent.Config{StoreDir: dir, Sealer: sealer, Counter: counter, Auditor: &agent.FakeAuditor{}}
	if _, err := agent.Startup(cfg, now.Add(time.Hour)); !errors.Is(err, store.ErrTampered) {
		t.Fatalf("err = %v, want store.ErrTampered", err)
	}
}

func TestStartup_ReverifyLKG_VerifiedUnderOldRootVersionStillLoadsAfterRotation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("agent-reverify-test-key-0123456")}
	counter := store.NewFakeMonotonicCounter()
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, rootKeys, _ := buildAndPersistLKG(t, st, apply.RelayDomain, "prod-db", "enforce", now)

	// Rotate the trust root forward. The LKG persisted above was
	// verified under version 1; it is NOT re-signed or re-verified
	// against version 2 -- it must still load (its own RootVersion=1 is
	// what re-verification checks against, via store.RootAtVersion, not
	// whatever the CURRENT root happens to be).
	v2Root := rotatedRoot(t, 2, now.Add(365*24*time.Hour), rootKeys)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg := agent.Config{
		StoreDir:         dir,
		Sealer:           sealer,
		Counter:          counter,
		InitialRootBytes: v2Root,
		Auditor:          &agent.FakeAuditor{},
	}
	res, err := agent.Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Startup after rotation: %v", err)
	}
	defer func() { _ = res.Store.Close() }()
	if res.TrustRoot.Version != 2 {
		t.Fatalf("TrustRoot.Version = %d, want 2 (rotation itself must still succeed)", res.TrustRoot.Version)
	}
	// The old root's blob must still be retained (it is still referenced
	// by the LKG's RootVersion=1), and the LKG itself must still be
	// readable.
	if _, version, ok, _ := res.Store.TrustRoot(); !ok || version != 2 {
		t.Fatalf("current persisted root version = %d (ok=%v), want 2", version, ok)
	}
	if _, ok := res.Store.Get(apply.RelayDomain); !ok {
		t.Fatalf("Get after rotation: ok = false, want the LKG to still be readable")
	}
}
