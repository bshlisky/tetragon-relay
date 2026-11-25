package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/dsse"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/trust"
)

func fixedNow() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// buildHybridTargetsRoot builds a minimal, self-signed root whose TARGETS
// role requires both ecdsa-p384 and mldsa-87 (so checkMLDSARequirement has
// something to flag), duplicating the same small amount of wire-shape
// knowledge internal/trust/helpers_test.go and internal/agent/helpers_test.go
// (package agent_test, not importable from this white-box file) do.
func buildHybridTargetsRoot(t *testing.T, now time.Time) ([]byte, error) {
	t.Helper()
	newECDSAKey := func() (id string, priv *ecdsa.PrivateKey, pubB64 string) {
		p, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa key: %v", err)
		}
		kid, err := trust.DeriveKeyID(&p.PublicKey)
		if err != nil {
			t.Fatalf("derive key id: %v", err)
		}
		der, _ := x509.MarshalPKIXPublicKey(&p.PublicKey)
		return string(kid), p, base64.StdEncoding.EncodeToString(der)
	}
	r1id, r1, r1pub := newECDSAKey()
	r2id, r2, r2pub := newECDSAKey()
	tid, _, tpub := newECDSAKey()
	lid, _, lpub := newECDSAKey()

	mpriv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("generate mldsa key: %v", err)
	}
	mder, err := x509.MarshalPKIXPublicKey(mpriv.PublicKey())
	if err != nil {
		t.Fatalf("marshal mldsa public key: %v", err)
	}
	mid := string(trust.DeriveKeyIDFromDER(mder))

	type keyEntry struct {
		KeyType      string `json:"keytype"`
		PublicKeyDER string `json:"public_key_der_b64"`
	}
	type role struct {
		KeyIDs          []string `json:"keyids"`
		Threshold       int      `json:"threshold"`
		RequireKeyTypes []string `json:"require_keytypes,omitempty"`
	}
	type roles struct {
		Root    role `json:"root"`
		Targets role `json:"targets"`
		Log     role `json:"log"`
	}
	type rootPayload struct {
		Schema  string              `json:"schema"`
		Version uint64              `json:"version"`
		Expires time.Time           `json:"expires"`
		Keys    map[string]keyEntry `json:"keys"`
		Roles   roles               `json:"roles"`
	}
	rp := rootPayload{
		Schema:  "relay.root.v1",
		Version: 1,
		Expires: now.Add(365 * 24 * time.Hour),
		Keys: map[string]keyEntry{
			r1id: {KeyType: "ecdsa-p384", PublicKeyDER: r1pub},
			r2id: {KeyType: "ecdsa-p384", PublicKeyDER: r2pub},
			tid:  {KeyType: "ecdsa-p384", PublicKeyDER: tpub},
			mid:  {KeyType: "mldsa-87", PublicKeyDER: base64.StdEncoding.EncodeToString(mder)},
			lid:  {KeyType: "ecdsa-p384", PublicKeyDER: lpub},
		},
		Roles: roles{
			Root:    role{KeyIDs: []string{r1id, r2id}, Threshold: 2, RequireKeyTypes: []string{"ecdsa-p384"}},
			Targets: role{KeyIDs: []string{tid, mid}, Threshold: 1, RequireKeyTypes: []string{"ecdsa-p384", "mldsa-87"}},
			Log:     role{KeyIDs: []string{lid}, Threshold: 1, RequireKeyTypes: []string{"ecdsa-p384"}},
		},
	}
	payload, err := json.Marshal(rp)
	if err != nil {
		t.Fatalf("marshal root payload: %v", err)
	}
	pae := dsse.PAE(trust.RootPayloadType, payload)
	sign := func(p *ecdsa.PrivateKey) string {
		digest := sha512.Sum384(pae)
		sig, _ := ecdsa.SignASN1(rand.Reader, p, digest[:])
		return base64.StdEncoding.EncodeToString(sig)
	}
	type wireSig struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	type wireEnvelope struct {
		PayloadType string    `json:"payloadType"`
		Payload     string    `json:"payload"`
		Signatures  []wireSig `json:"signatures"`
	}
	env := wireEnvelope{
		PayloadType: trust.RootPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []wireSig{
			{KeyID: r1id, Sig: sign(r1)},
			{KeyID: r2id, Sig: sign(r2)},
		},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b, nil
}

// This file is a white-box (package agent) test for error branches not
// otherwise reachable through the black-box startup_test.go suite:
// selftest.go's decode-failure branches (exercised by temporarily
// swapping the embedded constants is not possible since they are
// constants, so these instead directly unit-test the lower-level decode
// helpers' error wrapping with deliberately invalid base64) and
// checkMLDSARequirement's rejection branch, which requires
// Capabilities.MLDSAAvailable=false — never true in this development
// environment (RunCryptoSelfTest_Succeeds), so it must be constructed
// directly.

// buildECDSARoot builds a minimal, self-signed, ECDSA-only root at
// version, signed by (threshold 2 of) rootKeys, for building a chain to
// rotate away from in R4B-6's tests. If oldRootKeys is non-nil, the
// envelope is ALSO signed by threshold 2 of oldRootKeys, so it satisfies
// (*trust.Root).Update from a root built with oldRootKeys.
func buildECDSARoot(t *testing.T, version uint64, now time.Time, rootKeys []*ecdsa.PrivateKey, oldRootKeys []*ecdsa.PrivateKey) []byte {
	t.Helper()
	type keyEntry struct {
		KeyType      string `json:"keytype"`
		PublicKeyDER string `json:"public_key_der_b64"`
	}
	type role struct {
		KeyIDs          []string `json:"keyids"`
		Threshold       int      `json:"threshold"`
		RequireKeyTypes []string `json:"require_keytypes,omitempty"`
	}
	type roles struct {
		Root    role `json:"root"`
		Targets role `json:"targets"`
		Log     role `json:"log"`
	}
	type rootPayload struct {
		Schema  string              `json:"schema"`
		Version uint64              `json:"version"`
		Expires time.Time           `json:"expires"`
		Keys    map[string]keyEntry `json:"keys"`
		Roles   roles               `json:"roles"`
	}
	keyID := func(p *ecdsa.PrivateKey) string {
		id, err := trust.DeriveKeyID(&p.PublicKey)
		if err != nil {
			t.Fatalf("derive key id: %v", err)
		}
		return string(id)
	}
	pub := func(p *ecdsa.PrivateKey) string {
		der, _ := x509.MarshalPKIXPublicKey(&p.PublicKey)
		return base64.StdEncoding.EncodeToString(der)
	}
	tKey, lKey := mustTestECDSAKey(t), mustTestECDSAKey(t)
	keys := map[string]keyEntry{
		keyID(tKey): {KeyType: "ecdsa-p384", PublicKeyDER: pub(tKey)},
		keyID(lKey): {KeyType: "ecdsa-p384", PublicKeyDER: pub(lKey)},
	}
	rootIDs := make([]string, 0, len(rootKeys))
	for _, k := range rootKeys {
		keys[keyID(k)] = keyEntry{KeyType: "ecdsa-p384", PublicKeyDER: pub(k)}
		rootIDs = append(rootIDs, keyID(k))
	}
	rp := rootPayload{
		Schema:  "relay.root.v1",
		Version: version,
		Expires: now.Add(365 * 24 * time.Hour),
		Keys:    keys,
		Roles: roles{
			Root:    role{KeyIDs: rootIDs, Threshold: 2, RequireKeyTypes: []string{"ecdsa-p384"}},
			Targets: role{KeyIDs: []string{keyID(tKey)}, Threshold: 1, RequireKeyTypes: []string{"ecdsa-p384"}},
			Log:     role{KeyIDs: []string{keyID(lKey)}, Threshold: 1, RequireKeyTypes: []string{"ecdsa-p384"}},
		},
	}
	payload, err := json.Marshal(rp)
	if err != nil {
		t.Fatalf("marshal root payload: %v", err)
	}
	pae := dsse.PAE(trust.RootPayloadType, payload)
	sign := func(p *ecdsa.PrivateKey) string {
		digest := sha512.Sum384(pae)
		sig, _ := ecdsa.SignASN1(rand.Reader, p, digest[:])
		return base64.StdEncoding.EncodeToString(sig)
	}
	type wireSig struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	type wireEnvelope struct {
		PayloadType string    `json:"payloadType"`
		Payload     string    `json:"payload"`
		Signatures  []wireSig `json:"signatures"`
	}
	sigs := make([]wireSig, 0, 4)
	for _, k := range rootKeys[:2] {
		sigs = append(sigs, wireSig{KeyID: keyID(k), Sig: sign(k)})
	}
	for _, k := range oldRootKeys {
		sigs = append(sigs, wireSig{KeyID: keyID(k), Sig: sign(k)})
	}
	env := wireEnvelope{PayloadType: trust.RootPayloadType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: sigs}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

func mustTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	return p
}

// buildHybridTargetsRootChained is buildHybridTargetsRoot, parameterized
// by version and additionally signed by oldRootKeys too, so it can be
// adopted as a forward-chain step from a root built with
// buildECDSARoot's rootKeys (step-04b-review.md R4B-6).
func buildHybridTargetsRootChained(t *testing.T, version uint64, now time.Time, newRootKeys []*ecdsa.PrivateKey, oldRootKeys []*ecdsa.PrivateKey) []byte {
	t.Helper()
	type keyEntry struct {
		KeyType      string `json:"keytype"`
		PublicKeyDER string `json:"public_key_der_b64"`
	}
	type role struct {
		KeyIDs          []string `json:"keyids"`
		Threshold       int      `json:"threshold"`
		RequireKeyTypes []string `json:"require_keytypes,omitempty"`
	}
	type roles struct {
		Root    role `json:"root"`
		Targets role `json:"targets"`
		Log     role `json:"log"`
	}
	type rootPayload struct {
		Schema  string              `json:"schema"`
		Version uint64              `json:"version"`
		Expires time.Time           `json:"expires"`
		Keys    map[string]keyEntry `json:"keys"`
		Roles   roles               `json:"roles"`
	}
	keyID := func(p *ecdsa.PrivateKey) string {
		id, err := trust.DeriveKeyID(&p.PublicKey)
		if err != nil {
			t.Fatalf("derive key id: %v", err)
		}
		return string(id)
	}
	pub := func(p *ecdsa.PrivateKey) string {
		der, _ := x509.MarshalPKIXPublicKey(&p.PublicKey)
		return base64.StdEncoding.EncodeToString(der)
	}
	tKey, lKey := mustTestECDSAKey(t), mustTestECDSAKey(t)
	mpriv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("generate mldsa key: %v", err)
	}
	mder, err := x509.MarshalPKIXPublicKey(mpriv.PublicKey())
	if err != nil {
		t.Fatalf("marshal mldsa public key: %v", err)
	}
	mid := string(trust.DeriveKeyIDFromDER(mder))

	keys := map[string]keyEntry{
		keyID(tKey): {KeyType: "ecdsa-p384", PublicKeyDER: pub(tKey)},
		keyID(lKey): {KeyType: "ecdsa-p384", PublicKeyDER: pub(lKey)},
		mid:         {KeyType: "mldsa-87", PublicKeyDER: base64.StdEncoding.EncodeToString(mder)},
	}
	rootIDs := make([]string, 0, len(newRootKeys))
	for _, k := range newRootKeys {
		keys[keyID(k)] = keyEntry{KeyType: "ecdsa-p384", PublicKeyDER: pub(k)}
		rootIDs = append(rootIDs, keyID(k))
	}
	rp := rootPayload{
		Schema:  "relay.root.v1",
		Version: version,
		Expires: now.Add(365 * 24 * time.Hour),
		Keys:    keys,
		Roles: roles{
			Root:    role{KeyIDs: rootIDs, Threshold: 2, RequireKeyTypes: []string{"ecdsa-p384"}},
			Targets: role{KeyIDs: []string{keyID(tKey), mid}, Threshold: 1, RequireKeyTypes: []string{"ecdsa-p384", "mldsa-87"}},
			Log:     role{KeyIDs: []string{keyID(lKey)}, Threshold: 1, RequireKeyTypes: []string{"ecdsa-p384"}},
		},
	}
	payload, err := json.Marshal(rp)
	if err != nil {
		t.Fatalf("marshal root payload: %v", err)
	}
	pae := dsse.PAE(trust.RootPayloadType, payload)
	sign := func(p *ecdsa.PrivateKey) string {
		digest := sha512.Sum384(pae)
		sig, _ := ecdsa.SignASN1(rand.Reader, p, digest[:])
		return base64.StdEncoding.EncodeToString(sig)
	}
	type wireSig struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	type wireEnvelope struct {
		PayloadType string    `json:"payloadType"`
		Payload     string    `json:"payload"`
		Signatures  []wireSig `json:"signatures"`
	}
	sigs := make([]wireSig, 0, 4)
	for _, k := range newRootKeys[:2] {
		sigs = append(sigs, wireSig{KeyID: keyID(k), Sig: sign(k)})
	}
	for _, k := range oldRootKeys {
		sigs = append(sigs, wireSig{KeyID: keyID(k), Sig: sign(k)})
	}
	env := wireEnvelope{PayloadType: trust.RootPayloadType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: sigs}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

func TestEstablishTrustRoot_RefusesToAdoptRootRequiringUnavailableMLDSA(t *testing.T) {
	now := fixedNow()
	r1, r2, r3 := mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)
	v1Root := buildECDSARoot(t, 1, now, []*ecdsa.PrivateKey{r1, r2, r3}, nil)

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &testSealer{key: []byte("agent-internal-test-key-0123456")}
	counter := &testCounter{}
	st0, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st0.PersistTrustRoot(v1Root, 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	if err := st0.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Re-open so FirstBoot() reflects a realistic restart, not the
	// initial bootstrap Open above (st0 exists only to seed version 1).
	st, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = st.Close() }()

	r4, r5, r6 := mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)
	v2Root := buildHybridTargetsRootChained(t, 2, now, []*ecdsa.PrivateKey{r4, r5, r6}, []*ecdsa.PrivateKey{r1, r2})

	cfg := Config{AvailableRPMRoots: map[uint64][]byte{2: v2Root}}
	auditor := &FakeAuditor{}
	caps := Capabilities{MLDSAAvailable: false}

	root, err := establishTrustRoot(st, cfg, caps, now.Add(time.Hour), auditor)
	if err != nil {
		t.Fatalf("establishTrustRoot: %v", err)
	}
	if root.Version != 1 {
		t.Fatalf("Version = %d, want 1 (refused to adopt a root requiring unavailable mldsa-87)", root.Version)
	}
	found := false
	for _, e := range auditor.Events {
		if e.Step == "trust_root" && e.Err == nil && e.Detail != "" {
			if containsSubstr(e.Detail, "refusing to adopt") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no 'refusing to adopt' audit event; events = %+v", auditor.Events)
	}
}

func containsSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// testSealer/testCounter are minimal store.KeySealer/store.MonotonicCounter
// implementations for this white-box file, duplicating
// store.FakeKeySealer/store.FakeMonotonicCounter's shape (not importable
// as a dependency cycle concern here, but kept local and minimal since
// this file only needs one Open call).
type testSealer struct{ key []byte }

func (s *testSealer) Unseal() ([]byte, error) { return s.key, nil }

type testCounter struct{ v uint64 }

func (c *testCounter) Read() (uint64, error) { return c.v, nil }
func (c *testCounter) Increment() (uint64, error) {
	c.v++
	return c.v, nil
}

func TestStartupDegradedCondition_ReportsWhenPersistedRootRequiresUnavailableMLDSA(t *testing.T) {
	now := fixedNow()
	envelope, _ := buildHybridTargetsRoot(t, now)
	root, err := trust.LoadInitialRoot(envelope)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}

	degraded, reason := startupDegradedCondition(root, Capabilities{MLDSAAvailable: false}, &FakeAuditor{})
	if !degraded {
		t.Fatalf("degraded = false, want true")
	}
	if reason != degradedReasonMLDSAUnavailable {
		t.Fatalf("reason = %q, want %q", reason, degradedReasonMLDSAUnavailable)
	}

	degraded2, reason2 := startupDegradedCondition(root, Capabilities{MLDSAAvailable: true}, &FakeAuditor{})
	if degraded2 || reason2 != "" {
		t.Fatalf("degraded = (%v, %q), want (false, \"\") when ML-DSA is available", degraded2, reason2)
	}
}

// TestStartup_HybridRotationPersistedAndReloaded implements
// docs/reports/step-04b.md's "Known limitations" item for Part E3: "a
// hybrid rotation persisted and reloaded" -- a root rotating into a
// hybrid ecdsa+mldsa targets role, persisted, then a fresh Open reloading
// it.
func TestStartup_HybridRotationPersistedAndReloaded(t *testing.T) {
	now := fixedNow()
	r1, r2, r3 := mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)
	v1Root := buildECDSARoot(t, 1, now, []*ecdsa.PrivateKey{r1, r2, r3}, nil)

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	sealer := &testSealer{key: []byte("agent-internal-test-key-0123456")}
	counter := &testCounter{}
	cfg := Config{StoreDir: dir, Sealer: sealer, Counter: counter, InitialRootBytes: v1Root, Auditor: &FakeAuditor{}}

	res, err := Startup(cfg, now)
	if err != nil {
		t.Fatalf("first Startup: %v", err)
	}
	if err := res.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r4, r5, r6 := mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)
	v2Root := buildHybridTargetsRootChained(t, 2, now, []*ecdsa.PrivateKey{r4, r5, r6}, []*ecdsa.PrivateKey{r1, r2})
	cfg.InitialRootBytes = v2Root

	res2, err := Startup(cfg, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("rotation Startup: %v", err)
	}
	if res2.TrustRoot.Version != 2 {
		t.Fatalf("Version after rotation = %d, want 2", res2.TrustRoot.Version)
	}
	requireHybridTargets(t, res2.TrustRoot)
	if err := res2.Store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reload: a fresh Open/Startup with no RPM-shipped root configured
	// at all must reconstruct the exact same hybrid root purely from
	// the persisted bytes.
	cfg.InitialRootBytes = nil
	res3, err := Startup(cfg, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("reload Startup: %v", err)
	}
	defer func() { _ = res3.Store.Close() }()
	if res3.FirstBoot {
		t.Fatalf("FirstBoot = true on a reload, want false")
	}
	if res3.TrustRoot.Version != 2 {
		t.Fatalf("Version after reload = %d, want 2", res3.TrustRoot.Version)
	}
	requireHybridTargets(t, res3.TrustRoot)
}

func requireHybridTargets(t *testing.T, root *trust.Root) {
	t.Helper()
	role := root.TargetsRole()
	var hasECDSA, hasMLDSA bool
	for _, kt := range role.RequireKeyTypes {
		switch kt {
		case trust.KeyTypeECDSAP384:
			hasECDSA = true
		case trust.KeyTypeMLDSA87:
			hasMLDSA = true
		}
	}
	if !hasECDSA || !hasMLDSA {
		t.Fatalf("targets role RequireKeyTypes = %v, want both ecdsa-p384 and mldsa-87", role.RequireKeyTypes)
	}
}

func TestCheckMLDSARequirement_FlagsEachRoleNeedingIt(t *testing.T) {
	caps := Capabilities{MLDSAAvailable: false}

	// trust.Root's role accessors (RootRole/TargetsRole/LogRole) are
	// exported and return copies; build one directly via the package's
	// own exported construction path (LoadInitialRoot) rather than
	// reaching into unexported fields, matching how a real caller would
	// obtain a *trust.Root.
	now := fixedNow()
	envelope, _ := buildHybridTargetsRoot(t, now)
	root, err := trust.LoadInitialRoot(envelope)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}

	err = checkMLDSARequirement(root, caps, &FakeAuditor{})
	if !errors.Is(err, ErrMLDSAUnavailable) {
		t.Fatalf("err = %v, want ErrMLDSAUnavailable", err)
	}

	auditor := &FakeAuditor{}
	_ = checkMLDSARequirement(root, caps, auditor)
	found := false
	for _, e := range auditor.Events {
		if e.Step == "mldsa_requirement" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no mldsa_requirement audit event recorded")
	}
}

func TestCheckMLDSARequirement_NoOpWhenAvailableOrNilRoot(t *testing.T) {
	if err := checkMLDSARequirement(nil, Capabilities{MLDSAAvailable: false}, &FakeAuditor{}); err != nil {
		t.Fatalf("nil root: err = %v, want nil", err)
	}
	now := fixedNow()
	envelope, _ := buildHybridTargetsRoot(t, now)
	root, err := trust.LoadInitialRoot(envelope)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	if err := checkMLDSARequirement(root, Capabilities{MLDSAAvailable: true}, &FakeAuditor{}); err != nil {
		t.Fatalf("MLDSAAvailable=true: err = %v, want nil", err)
	}
}

func TestRunCryptoSelfTest_ECDSAFailureRefusesToStart(t *testing.T) {
	_, err := runCryptoSelfTest("not base64!!", selfTestECDSAPubDERB64, selfTestECDSASigB64, selfTestMLDSA87RawPubB64, selfTestMLDSA87SigB64)
	if !errors.Is(err, ErrECDSASelfTestFailed) {
		t.Fatalf("err = %v, want ErrECDSASelfTestFailed", err)
	}
}

func TestRunCryptoSelfTest_MLDSAFailureIsNotFatal(t *testing.T) {
	caps, err := runCryptoSelfTest(selfTestMessageB64, selfTestECDSAPubDERB64, selfTestECDSASigB64, "not base64!!", selfTestMLDSA87SigB64)
	if err != nil {
		t.Fatalf("err = %v, want nil (an ML-DSA failure must not refuse to start)", err)
	}
	if caps.MLDSAAvailable {
		t.Fatalf("MLDSAAvailable = true, want false")
	}
	if caps.MLDSAErr == nil {
		t.Fatalf("MLDSAErr = nil, want the decode error")
	}
}

func TestVerifyECDSASelfTest_EachFailureBranch(t *testing.T) {
	good := selfTestMessageB64
	goodPub := selfTestECDSAPubDERB64
	goodSig := selfTestECDSASigB64

	if err := verifyECDSASelfTest(good, goodPub, goodSig); err != nil {
		t.Fatalf("the real vector must pass: %v", err)
	}
	if err := verifyECDSASelfTest("not base64!!", goodPub, goodSig); err == nil {
		t.Fatalf("expected a message decode error")
	}
	if err := verifyECDSASelfTest(good, "not base64!!", goodSig); err == nil {
		t.Fatalf("expected a public key decode error")
	}
	if err := verifyECDSASelfTest(good, goodPub, "not base64!!"); err == nil {
		t.Fatalf("expected a signature decode error")
	}
	// Valid base64 that is not a parseable SPKI at all.
	notASPKI := base64.StdEncoding.EncodeToString([]byte("not a real DER key"))
	if err := verifyECDSASelfTest(good, notASPKI, goodSig); err == nil {
		t.Fatalf("expected a public key parse error")
	}
	// A structurally valid, but non-ECDSA, SPKI (ML-DSA-87's own test
	// vector's public key).
	if err := verifyECDSASelfTest(good, selfTestMLDSA87RawPubB64AsFakeDER(t), goodSig); err == nil {
		t.Fatalf("expected an error for a non-ECDSA public key")
	}
	// A well-formed ECDSA key and signature, but over the wrong message
	// (or signed by a different key): the signature must not verify.
	otherMsg := base64.StdEncoding.EncodeToString([]byte("a different message entirely"))
	if err := verifyECDSASelfTest(otherMsg, goodPub, goodSig); err == nil {
		t.Fatalf("expected a verification failure for the wrong message")
	}
}

// selfTestMLDSA87RawPubB64AsFakeDER returns something that decodes as
// valid base64 but is not a parseable SubjectPublicKeyInfo, reusing the
// ML-DSA raw public key bytes (which are not DER) purely as "valid
// base64, invalid DER" filler.
func selfTestMLDSA87RawPubB64AsFakeDER(t *testing.T) string {
	t.Helper()
	return selfTestMLDSA87RawPubB64
}

func TestVerifyMLDSASelfTest_EachFailureBranch(t *testing.T) {
	good := selfTestMessageB64
	goodPub := selfTestMLDSA87RawPubB64
	goodSig := selfTestMLDSA87SigB64

	if err := verifyMLDSASelfTest(good, goodPub, goodSig); err != nil {
		t.Fatalf("the real vector must pass: %v", err)
	}
	if err := verifyMLDSASelfTest("not base64!!", goodPub, goodSig); err == nil {
		t.Fatalf("expected a message decode error")
	}
	if err := verifyMLDSASelfTest(good, "not base64!!", goodSig); err == nil {
		t.Fatalf("expected a public key decode error")
	}
	if err := verifyMLDSASelfTest(good, goodPub, "not base64!!"); err == nil {
		t.Fatalf("expected a signature decode error")
	}
	// A wrong-size raw public key: dsse.VerifyMLDSA87 wraps
	// mldsa.NewPublicKey's construction error.
	tooShort := base64.StdEncoding.EncodeToString([]byte("too short"))
	if err := verifyMLDSASelfTest(good, tooShort, goodSig); err == nil {
		t.Fatalf("expected a key-construction error for a too-short public key")
	}
	otherMsg := base64.StdEncoding.EncodeToString([]byte("a different message entirely"))
	if err := verifyMLDSASelfTest(otherMsg, goodPub, goodSig); err == nil {
		t.Fatalf("expected a verification failure for the wrong message")
	}
}
