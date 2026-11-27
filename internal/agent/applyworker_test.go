package agent_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/trust"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

const testHostUUID = "11111111-1111-4111-8111-111111111111"

type lockedAuditor struct {
	mu     sync.Mutex
	events []agent.AuditEvent
}

func (a *lockedAuditor) Record(e agent.AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
}

func (a *lockedAuditor) hasDetail(step, substr string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Step == step && strings.Contains(e.Detail, substr) {
			return true
		}
	}
	return false
}

func (a *lockedAuditor) has(step string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Step == step {
			return true
		}
	}
	return false
}

type fixedVersion struct{ v string }

func (f fixedVersion) GetVersion(context.Context) (string, error) { return f.v, nil }

// scriptedEngine stands in for *apply.Engine. On StatusApplied it calls
// the CommitOnPut exactly as the real engine does after a passed health
// window. block, if non-nil, holds every Apply until it is closed.
type scriptedEngine struct {
	commit *agent.CommitOnPut
	status apply.Status
	err    error
	nilRes bool
	block  chan struct{}

	mu      sync.Mutex
	applied []uint64
	started chan uint64

	// reports is the scripted sequence of Reconcile results (the last
	// one repeats); reassertCalls counts Reconcile(true) calls.
	reports       []*apply.DriftReport
	reconcileErr  error
	reconcileCall int
	reassertCalls int
}

func (e *scriptedEngine) Reconcile(_ context.Context, reassert bool) (*apply.DriftReport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if reassert {
		e.reassertCalls++
	}
	if e.reconcileErr != nil {
		return nil, e.reconcileErr
	}
	if len(e.reports) == 0 {
		return &apply.DriftReport{InSync: true}, nil
	}
	i := e.reconcileCall
	if i >= len(e.reports) {
		i = len(e.reports) - 1
	}
	e.reconcileCall++
	r := *e.reports[i]
	return &r, nil
}

func (e *scriptedEngine) Apply(ctx context.Context, r *verify.Result) (*apply.Result, error) {
	if e.started != nil {
		e.started <- r.Bundle.Epoch
	}
	if e.block != nil {
		select {
		case <-e.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	e.mu.Lock()
	e.applied = append(e.applied, r.Bundle.Epoch)
	e.mu.Unlock()
	if e.nilRes {
		return nil, e.err
	}
	if e.status == apply.StatusApplied {
		set, err := apply.ResolveLKGSet(r.Bundle, apply.RealPolicyParser{})
		if err != nil {
			return nil, err
		}
		set.RawEnvelope, set.RootVersion = r.RawEnvelope, r.RootVersion
		_ = e.commit.Put(apply.RelayDomain, set) // the real engine audits, never fails, on a Put error
	}
	return &apply.Result{Status: e.status, Detail: "scripted " + e.status.String()}, e.err
}

type pipeline struct {
	t        *testing.T
	now      time.Time
	st       *store.Store
	dir      string
	sm       *agent.StateMachine
	link     *agent.Link
	outbox   *agent.Outbox
	engine   *scriptedEngine
	auditor  *lockedAuditor
	worker   *agent.ApplyWorker
	targets  *genKey
	rootKeys []*genKey
	rootEnv  []byte
	liveness *agent.LivenessRegistry
}

type pipelineOpts struct {
	enforceAllowed bool
	status         apply.Status
	block          bool
	smState        agent.State
	failCommit     bool
}

func newPipeline(t *testing.T, o pipelineOpts) *pipeline {
	t.Helper()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, &store.FakeKeySealer{Key: []byte("test-hmac-key-0123456789abcdef")}, store.NewFakeMonotonicCounter())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rootEnv, rootKeys, targetsKey := standardRootWithTargetsKey(t, 1, now.Add(300*24*time.Hour))
	root, err := trust.LoadInitialRoot(rootEnv)
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	ts, err := agent.NewTrustState(root)
	if err != nil {
		t.Fatal(err)
	}
	auditor := &lockedAuditor{}
	sm, _ := agent.NewStateMachine(auditor)
	for _, e := range []agent.Event{agent.EventJoinTokenValid, agent.EventSVIDIssued, agent.EventHelloAck, agent.EventInSync} {
		if err := sm.Fire(e); err != nil {
			t.Fatal(err)
		}
	}
	if o.smState == agent.StateDegraded {
		if err := sm.Fire(agent.EventDegradedCondition); err != nil {
			t.Fatal(err)
		}
	}
	clock := func() time.Time { return now }
	link, _ := agent.NewLink(clock, 15*time.Second)
	link.Up(func() {})
	outbox, _ := agent.NewOutbox(&agent.FakeAuditor{})
	alerter, _ := agent.NewAlerter(outbox, auditor, clock)
	liveness, _ := agent.NewLivenessRegistry(time.Now)
	commit := &agent.CommitOnPut{Store: st}
	if o.failCommit {
		commit = &agent.CommitOnPut{Store: failingCommitStore{st}}
	}
	engine := &scriptedEngine{commit: commit, status: o.status, started: make(chan uint64, 8)}
	if o.block {
		engine.block = make(chan struct{})
	}
	w, err := agent.NewApplyWorker(agent.ApplyWorkerConfig{
		Deps: agent.BundleDeps{
			Store: st, Roots: st, Commit: commit, Trust: ts, Engine: engine, Reconciler: engine, Version: fixedVersion{"v1.8.0"},
			HostCaps: allCaps{}, EnforceAllowed: o.enforceAllowed, Crypto: agent.Capabilities{MLDSAAvailable: true},
			HostUUID: testHostUUID, AllowedScopes: []string{"prod"},
			Digest: func(context.Context) ([]byte, error) { return []byte{0xd1}, nil },
		},
		SM: sm, Link: link, Outbox: outbox, Alerter: alerter, Auditor: auditor, Liveness: liveness,
		Clock: clock, HealthWindow: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewApplyWorker: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	t.Cleanup(func() {
		if engine.block != nil {
			select {
			case <-engine.block:
			default:
				close(engine.block)
			}
		}
		cancel()
		<-done
	})
	if err := st.PersistTrustRoot(rootEnv, 1); err != nil {
		t.Fatalf("PersistTrustRoot: %v", err)
	}
	return &pipeline{t: t, now: now, st: st, dir: dir, sm: sm, link: link, outbox: outbox, engine: engine, auditor: auditor, worker: w, targets: targetsKey, rootKeys: rootKeys, rootEnv: rootEnv, liveness: liveness}
}

type allCaps struct{}

func (allCaps) KprobeOverride() bool { return true }
func (allCaps) LSMBPF() bool         { return true }

func (p *pipeline) bundle(mode string, epoch uint64, names ...string) []byte {
	specs := make([]bundlePolicySpec, 0, len(names))
	for _, n := range names {
		specs = append(specs, bundlePolicySpec{name: n, version: 1, yaml: minimalPolicyYAML(n)})
	}
	return buildBundleEnvelope(p.t, p.targets, "prod", mode, epoch, p.now, specs)
}

// next waits for the next ApplyResult or Alert in the outbox.
func (p *pipeline) next() *controlv1.AgentMessage {
	p.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if m := p.outbox.Peek(); m != nil {
			p.outbox.Pop(m)
			return m
		}
		select {
		case <-p.outbox.Notify():
		case <-deadline:
			p.t.Fatal("no outbox message within 10s")
			return nil
		}
	}
}

func (p *pipeline) nextResult() *controlv1.ApplyResult {
	p.t.Helper()
	for {
		m := p.next()
		if r := m.GetApplyResult(); r != nil {
			return r
		}
	}
}

func TestApplyWorker_MonitorThenEnforceAppliedAndCommitted(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied})
	p.worker.SubmitBundle(p.bundle("monitor", 1, "watch-exec"))
	r := p.nextResult()
	if r.GetStatus() != controlv1.ApplyResult_APPLIED || r.GetEpoch() != 1 || len(r.GetBundleDigest()) != 32 || string(r.GetLoadedDigestAfter()) != "\xd1" {
		t.Fatalf("monitor result = %v", r)
	}
	if e, _ := p.st.Current("prod"); e != 1 {
		t.Fatalf("epoch after monitor apply = %d, want 1", e)
	}
	if seen, _ := p.st.SeenInMonitor("prod", "watch-exec"); !seen {
		t.Fatal("monitor history not recorded")
	}
	p.worker.SubmitBundle(p.bundle("enforce", 2, "watch-exec"))
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_APPLIED || r.GetEpoch() != 2 {
		t.Fatalf("enforce result = %v", r)
	}
	if set, ok := p.st.Get(apply.RelayDomain); !ok || set.Mode != "enforce" {
		t.Fatalf("LKG after enforce = %+v, %v", set, ok)
	}
	if got := p.sm.Current(); got != agent.StateSteady {
		t.Fatalf("state = %s, want STEADY", got)
	}
}

func TestApplyWorker_Rejections(t *testing.T) {
	p := newPipeline(t, pipelineOpts{status: apply.StatusApplied})
	// Bad signature: a different key.
	bad := buildBundleEnvelope(t, mustKey(t), "prod", "monitor", 1, p.now, []bundlePolicySpec{{name: "a", version: 1, yaml: minimalPolicyYAML("a")}})
	p.worker.SubmitBundle(bad)
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_REJECTED_SIGNATURE {
		t.Fatalf("bad signature: %v", r)
	}
	// Scope not allowed.
	other := buildBundleEnvelope(t, p.targets, "other", "monitor", 1, p.now, []bundlePolicySpec{{name: "a", version: 1, yaml: minimalPolicyYAML("a")}})
	p.worker.SubmitBundle(other)
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_REJECTED_TARGET {
		t.Fatalf("scope: %v", r)
	}
	// Enforce without fresh host facts.
	p.worker.SubmitBundle(p.bundle("enforce", 1, "a"))
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_REJECTED_CAPABILITY || r.GetEpoch() != 1 {
		t.Fatalf("enforce without facts: %v", r)
	}
	if len(p.engine.applied) != 0 {
		t.Fatalf("engine ran for a rejected bundle: %v", p.engine.applied)
	}
	if e, _ := p.st.Current("prod"); e != 0 {
		t.Fatalf("epoch moved on rejection: %d", e)
	}
}

func TestApplyWorker_GuardrailRejectRaisesAlert(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied})
	// G5: an enforce bundle with an enforcement action never seen in monitor mode.
	yaml := "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: kill-canary\nspec:\n  kprobes:\n  - call: \"do_something\"\n    selectors:\n    - matchBinaries:\n      - operator: \"In\"\n        values:\n        - \"/usr/local/bin/canary\"\n      matchActions:\n      - action: \"Sigkill\"\n"
	env := buildBundleEnvelope(t, p.targets, "prod", "enforce", 1, p.now, []bundlePolicySpec{{name: "kill-canary", version: 1, yaml: yaml}})
	p.worker.SubmitBundle(env)
	var alert *controlv1.Alert
	var result *controlv1.ApplyResult
	for alert == nil || result == nil {
		m := p.next()
		if a := m.GetAlert(); a != nil {
			alert = a
		}
		if r := m.GetApplyResult(); r != nil {
			result = r
		}
	}
	if result.GetStatus() != controlv1.ApplyResult_REJECTED_GUARDRAIL || !strings.Contains(result.GetDetail(), "G5") {
		t.Fatalf("result = %v", result)
	}
	if alert.GetKind() != controlv1.Alert_GUARDRAIL_REJECT || !strings.Contains(alert.GetDetail(), "G5") {
		t.Fatalf("alert = %v", alert)
	}
}

func TestApplyWorker_TamperedStoreRejectsEveryBundle(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied})
	p.worker.SubmitBundle(p.bundle("monitor", 1, "a"))
	_ = p.nextResult()
	// Corrupt every blob so the next LKG read marks the store TAMPERED.
	blobs, _ := os.ReadDir(p.dir + "/blobs")
	for _, b := range blobs {
		if err := os.WriteFile(p.dir+"/blobs/"+b.Name(), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := p.st.Get(apply.RelayDomain); ok {
		t.Fatal("corrupt LKG still readable")
	}
	p.worker.SubmitBundle(p.bundle("monitor", 2, "a"))
	r := p.nextResult()
	if r.GetStatus() != controlv1.ApplyResult_REJECTED_TAMPERED || !strings.Contains(r.GetDetail(), "TAMPERED") {
		t.Fatalf("tampered: %v", r)
	}
	if !p.auditor.hasDetail("alert", "kind=TAMPER") {
		t.Fatal("no Alert TAMPER for a store found TAMPERED at runtime")
	}
}

func TestApplyWorker_SupersededPendingAndVerifyAtDequeue(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied, block: true})
	first := p.bundle("monitor", 2, "a")
	p.worker.SubmitBundle(first)
	<-p.engine.started // first is applying
	if p.sm.Current() != agent.StateApplying {
		t.Fatalf("state during apply = %s", p.sm.Current())
	}
	superseded := p.bundle("monitor", 3, "b")
	p.worker.SubmitBundle(superseded)
	// The same epoch as the bundle being applied: valid when it
	// arrives (store epoch 0), stale once the first apply commits.
	replay := p.bundle("monitor", 2, "c")
	p.worker.SubmitBundle(replay)

	r := p.nextResult()
	if r.GetStatus() != controlv1.ApplyResult_SUPERSEDED || r.GetDetail() != "superseded" || string(r.GetBundleDigest()) != string(digestOf(superseded)) {
		t.Fatalf("superseded result = %v", r)
	}
	close(p.engine.block)
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_APPLIED || r.GetEpoch() != 2 {
		t.Fatalf("first result = %v", r)
	}
	r = p.nextResult()
	if r.GetStatus() != controlv1.ApplyResult_REJECTED_EPOCH || r.GetDetail() == "superseded" || string(r.GetBundleDigest()) != string(digestOf(replay)) {
		t.Fatalf("replay verified at dequeue = %v", r)
	}
	if got := p.engine.applied; len(got) != 1 {
		t.Fatalf("engine applied %v, want only the first bundle", got)
	}
}

func TestApplyWorker_NotSteadyIsNotApplied(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied, smState: agent.StateDegraded})
	p.worker.SubmitBundle(p.bundle("monitor", 1, "a"))
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_REJECTED_AGENT_STATE || !strings.Contains(r.GetDetail(), "DEGRADED") {
		t.Fatalf("result = %v", r)
	}
	if len(p.engine.applied) != 0 {
		t.Fatal("engine ran in DEGRADED")
	}
}

func TestApplyWorker_OutcomeMapping(t *testing.T) {
	cases := []struct {
		name      string
		status    apply.Status
		nilRes    bool
		want      controlv1.ApplyResult_Status
		wantState agent.State
		wantAlert bool
	}{
		{"rolled back", apply.StatusRolledBack, false, controlv1.ApplyResult_ROLLED_BACK, agent.StateSteady, false},
		{"apply failed", apply.StatusApplyFailed, false, controlv1.ApplyResult_APPLY_FAILED, agent.StateSteady, false},
		{"rollback failed", apply.StatusRollbackFailed, false, controlv1.ApplyResult_ROLLBACK_FAILED, agent.StateDegraded, true},
		{"engine error", apply.StatusApplied, true, controlv1.ApplyResult_APPLY_FAILED, agent.StateSteady, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: c.status})
			p.engine.nilRes = c.nilRes
			if c.nilRes {
				p.engine.err = errors.New("tetragon version unsupported")
			}
			p.worker.SubmitBundle(p.bundle("monitor", 1, "a"))
			gotAlerts := map[controlv1.Alert_Kind]bool{}
			var r *controlv1.ApplyResult
			for r == nil {
				m := p.next()
				if a := m.GetAlert(); a != nil {
					gotAlerts[a.GetKind()] = true
				}
				r = m.GetApplyResult()
			}
			if r.GetStatus() != c.want {
				t.Fatalf("status = %s, want %s (%s)", r.GetStatus(), c.want, r.GetDetail())
			}
			if c.wantAlert {
				// The alerts are pushed after the result: ROLLBACK_FAILED,
				// then DRIFT (ADR 0037).
				for len(gotAlerts) < 2 {
					a := p.next().GetAlert()
					if a == nil {
						t.Fatal("expected an alert after the ApplyResult")
					}
					gotAlerts[a.GetKind()] = true
				}
				if !gotAlerts[controlv1.Alert_ROLLBACK_FAILED] || !gotAlerts[controlv1.Alert_DRIFT] {
					t.Fatalf("alerts for ROLLBACK_FAILED = %v, want ROLLBACK_FAILED and DRIFT", gotAlerts)
				}
			}
			if got := p.sm.Current(); got != c.wantState {
				t.Fatalf("state = %s, want %s", got, c.wantState)
			}
			if e, _ := p.st.Current("prod"); e != 0 {
				t.Fatalf("epoch persisted for a non-APPLIED outcome: %d", e)
			}
		})
	}
}

func TestApplyWorker_CommitFailureIsNotReportedApplied(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied, failCommit: true})
	p.worker.SubmitBundle(p.bundle("monitor", 1, "a"))
	r := p.nextResult()
	if r.GetStatus() != controlv1.ApplyResult_APPLY_FAILED || !strings.Contains(r.GetDetail(), "disk full") {
		t.Fatalf("result = %v", r)
	}
	if !p.auditor.has("apply_commit_failed") {
		t.Fatal("no apply_commit_failed audit record")
	}
	if e, _ := p.st.Current("prod"); e != 0 {
		t.Fatalf("epoch = %d after a failed commit", e)
	}
}

// failingCommitStore wraps a real store but fails CommitApplied.
type failingCommitStore struct{ *store.Store }

func (failingCommitStore) CommitApplied(store.AppliedCommit) error {
	return fmt.Errorf("disk full")
}

func digestOf(env []byte) []byte {
	sum := sha256.Sum256(env)
	return sum[:]
}

// rotatedRootWithTargets is rotatedRootWithKeys, also returning the new
// root's targets key, so a test can sign bundles under the rotated root.
func rotatedRootWithTargets(t *testing.T, version int, expires time.Time, oldRootKeys []*genKey) (envelope []byte, newRootKeys []*genKey, targets *genKey) {
	t.Helper()
	r1, r2, r3 := mustKey(t), mustKey(t), mustKey(t)
	tk, lk := mustKey(t), mustKey(t)
	payload := buildRootPayload(version, expires, []*genKey{r1, r2, r3, tk, lk}, roleOf([]*genKey{r1, r2, r3}, 2), roleOf([]*genKey{tk}, 1), roleOf([]*genKey{lk}, 1))
	return signEnvelope(trust.RootPayloadType, payload, oldRootKeys[0], oldRootKeys[1], r1, r2), []*genKey{r1, r2, r3}, tk
}

func (p *pipeline) rootVersion() uint64 {
	_, v, _, err := p.st.TrustRoot()
	if err != nil {
		p.t.Fatalf("TrustRoot: %v", err)
	}
	return v
}

func (p *pipeline) waitRootVersion(want uint64) {
	p.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for p.rootVersion() != want {
		if time.Now().After(deadline) {
			p.t.Fatalf("persisted root version = %d, want %d", p.rootVersion(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func (p *pipeline) nextAlert() *controlv1.Alert {
	p.t.Helper()
	for {
		if a := p.next().GetAlert(); a != nil {
			return a
		}
	}
}

func TestTrustUpdate_ChainAdoptedPersistedAndUsedForBundles(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied})
	exp := p.now.Add(200 * 24 * time.Hour)
	v2, v2Keys, _ := rotatedRootWithTargets(t, 2, exp, p.rootKeys)
	v3, _, v3Targets := rotatedRootWithTargets(t, 3, exp, v2Keys)
	// The current version (1) is included first: it is skipped, not an error.
	p.worker.SubmitTrustUpdate([][]byte{p.rootEnv, v2, v3})
	p.worker.SubmitBundle(buildBundleEnvelope(t, v3Targets, "prod", "monitor", 1, p.now, []bundlePolicySpec{{name: "a", version: 1, yaml: minimalPolicyYAML("a")}}))
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_APPLIED {
		t.Fatalf("bundle under root v3: %v", r)
	}
	if p.rootVersion() != 3 {
		t.Fatalf("persisted root version = %d, want 3", p.rootVersion())
	}
	// The old targets key no longer verifies.
	p.worker.SubmitBundle(p.bundle("monitor", 2, "a"))
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_REJECTED_SIGNATURE {
		t.Fatalf("bundle under the old targets key: %v", r)
	}
	if !p.auditor.has("trust_update_skipped") || !p.auditor.has("trust_update_applied") {
		t.Fatal("missing trust update audit records")
	}
}

func TestTrustUpdate_PartialChainKeepsLastGoodRoot(t *testing.T) {
	p := newPipeline(t, pipelineOpts{status: apply.StatusApplied})
	exp := p.now.Add(200 * 24 * time.Hour)
	v2, _, _ := rotatedRootWithTargets(t, 2, exp, p.rootKeys)
	bad, _, _ := rotatedRootWithTargets(t, 3, exp, []*genKey{mustKey(t), mustKey(t)}) // not signed by v2's root keys
	p.worker.SubmitTrustUpdate([][]byte{v2, bad})
	a := p.nextAlert()
	if a.GetKind() != controlv1.Alert_TRUST_UPDATE_REJECTED || !strings.Contains(a.GetDetail(), "keeping version 2") {
		t.Fatalf("alert = %v", a)
	}
	if p.rootVersion() != 2 {
		t.Fatalf("persisted root version = %d, want 2 (the last good step)", p.rootVersion())
	}
	if !p.auditor.has("trust_update_rejected") {
		t.Fatal("rejection not audited")
	}
}

func TestTrustUpdate_EmptyIsRejected(t *testing.T) {
	p := newPipeline(t, pipelineOpts{status: apply.StatusApplied})
	p.worker.SubmitTrustUpdate(nil)
	if a := p.nextAlert(); !strings.Contains(a.GetDetail(), "0 entries") {
		t.Fatalf("alert = %v", a)
	}
}

// TestTrustUpdate_WaitsForTheApplyInProgress: a trust update that arrives
// during a bundle apply is not processed until the apply ends (C2).
func TestTrustUpdate_WaitsForTheApplyInProgress(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied, block: true})
	v2, _, _ := rotatedRootWithTargets(t, 2, p.now.Add(200*24*time.Hour), p.rootKeys)
	p.worker.SubmitBundle(p.bundle("monitor", 1, "a"))
	<-p.engine.started
	p.worker.SubmitTrustUpdate([][]byte{v2})
	time.Sleep(50 * time.Millisecond)
	if p.rootVersion() != 1 {
		t.Fatalf("root changed to %d during an apply", p.rootVersion())
	}
	close(p.engine.block)
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_APPLIED {
		t.Fatalf("result = %v", r)
	}
	p.waitRootVersion(2)
}

func TestTrustUpdate_TamperedStoreRejects(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied})
	p.worker.SubmitBundle(p.bundle("monitor", 1, "a"))
	_ = p.nextResult()
	blobs, _ := os.ReadDir(p.dir + "/blobs")
	for _, b := range blobs {
		_ = os.WriteFile(p.dir+"/blobs/"+b.Name(), []byte("x"), 0o600)
	}
	_, _ = p.st.Get(apply.RelayDomain) // marks the store TAMPERED
	v2, _, _ := rotatedRootWithTargets(t, 2, p.now.Add(200*24*time.Hour), p.rootKeys)
	p.worker.SubmitTrustUpdate([][]byte{v2})
	if a := p.nextAlert(); !strings.Contains(a.GetDetail(), "TAMPERED") {
		t.Fatalf("alert = %v", a)
	}
}

func (p *pipeline) reconcileCalls() int {
	p.engine.mu.Lock()
	defer p.engine.mu.Unlock()
	return p.engine.reconcileCall
}

func (p *pipeline) reasserts() int {
	p.engine.mu.Lock()
	defer p.engine.mu.Unlock()
	return p.engine.reassertCalls
}

// cycle requests one reconcile cycle and waits until it has made want
// Reconcile calls in total (including re-asserts).
func (p *pipeline) cycle(restarted bool, want int) {
	p.t.Helper()
	p.worker.RequestReconcile(restarted)
	deadline := time.Now().Add(5 * time.Second)
	for p.reconcileCalls() < want {
		if time.Now().After(deadline) {
			p.t.Fatalf("reconcile calls = %d, want %d", p.reconcileCalls(), want)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let the cycle's transitions land
}

func drift(missing ...string) *apply.DriftReport {
	return &apply.DriftReport{Missing: missing}
}

func TestReconcile_DriftReassertHolds(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied})
	p.worker.SubmitBundle(p.bundle("monitor", 1, "a"))
	_ = p.nextResult()
	p.engine.mu.Lock()
	p.engine.reports = []*apply.DriftReport{drift("a-v1-x"), {Reasserted: true}, {InSync: true}}
	p.engine.mu.Unlock()
	p.cycle(false, 3)
	a := p.nextAlert()
	if a.GetKind() != controlv1.Alert_DRIFT || !strings.Contains(a.GetDetail(), "lkg_bundle_digest=") || !strings.Contains(a.GetDetail(), "loaded_digest=d1") || !strings.Contains(a.GetDetail(), "missing=[a-v1-x]") {
		t.Fatalf("alert = %v", a)
	}
	if strings.Contains(a.GetDetail(), "lkg_bundle_digest= ") {
		t.Fatalf("LKG digest missing: %q", a.GetDetail())
	}
	if p.sm.Current() != agent.StateSteady || p.reasserts() != 1 {
		t.Fatalf("state = %s, reasserts = %d; want STEADY, 1", p.sm.Current(), p.reasserts())
	}
	if !p.auditor.has("drift_reasserted") {
		t.Fatal("no drift_reasserted audit")
	}
}

func TestReconcile_DriftReassertFailsStaysInDriftAndAlertsEachCycle(t *testing.T) {
	p := newPipeline(t, pipelineOpts{status: apply.StatusApplied})
	p.engine.reports = []*apply.DriftReport{drift("x"), {Reasserted: false}, drift("x")}
	p.cycle(false, 2)
	if p.sm.Current() != agent.StateDrift || p.reasserts() != 1 {
		t.Fatalf("state = %s, reasserts = %d; want DRIFT, 1", p.sm.Current(), p.reasserts())
	}
	_ = p.nextAlert()
	// Next cycle: still drifted, no second re-assert, alert again (the
	// fixed test clock keeps it inside the rate limit, so it is audited
	// as suppressed).
	p.cycle(false, 3)
	if p.sm.Current() != agent.StateDrift || p.reasserts() != 1 {
		t.Fatalf("second cycle: state = %s, reasserts = %d", p.sm.Current(), p.reasserts())
	}
	if !p.auditor.has("alert_suppressed") || !p.auditor.has("drift_reassert_failed") {
		t.Fatal("expected the repeat DRIFT alert to be rate-limited and the failed re-assert audited")
	}
	// A Tetragon restart starts a new episode: one more re-assert.
	p.engine.mu.Lock()
	p.engine.reports = []*apply.DriftReport{drift("x"), {Reasserted: true}, {InSync: true}}
	p.engine.reconcileCall = 0
	p.engine.mu.Unlock()
	p.cycle(true, 3)
	if p.sm.Current() != agent.StateSteady || p.reasserts() != 2 {
		t.Fatalf("after restart: state = %s, reasserts = %d; want STEADY, 2", p.sm.Current(), p.reasserts())
	}
}

func TestReconcile_DriftClearsOnItsOwn(t *testing.T) {
	p := newPipeline(t, pipelineOpts{status: apply.StatusApplied})
	p.engine.reports = []*apply.DriftReport{drift("x"), {Reasserted: false}, drift("x"), {InSync: true}}
	p.cycle(false, 2) // drift, re-assert does not hold
	p.cycle(false, 3) // still drifted
	p.cycle(false, 4) // in sync on its own
	if p.sm.Current() != agent.StateSteady || !p.auditor.has("drift_resolved") {
		t.Fatalf("state = %s", p.sm.Current())
	}
}

func TestReconcile_ErrorAndTamperedStore(t *testing.T) {
	p := newPipeline(t, pipelineOpts{enforceAllowed: true, status: apply.StatusApplied})
	p.engine.mu.Lock()
	p.engine.reconcileErr = errors.New("tetragon down")
	p.engine.mu.Unlock()
	p.worker.RequestReconcile(false)
	deadline := time.Now().Add(5 * time.Second)
	for !p.auditor.has("reconcile_failed") {
		if time.Now().After(deadline) {
			t.Fatal("no reconcile_failed audit")
		}
		time.Sleep(time.Millisecond)
	}
	p.engine.mu.Lock()
	p.engine.reconcileErr = nil
	p.engine.mu.Unlock()

	p.worker.SubmitBundle(p.bundle("monitor", 1, "a"))
	_ = p.nextResult()
	blobs, _ := os.ReadDir(p.dir + "/blobs")
	for _, b := range blobs {
		_ = os.WriteFile(p.dir+"/blobs/"+b.Name(), []byte("x"), 0o600)
	}
	_, _ = p.st.Get(apply.RelayDomain)
	before := p.reconcileCalls()
	p.worker.RequestReconcile(false)
	p.worker.RequestReconcile(false)
	deadline = time.Now().Add(5 * time.Second)
	for !p.auditor.has("reconcile_skipped") {
		if time.Now().After(deadline) {
			t.Fatal("no reconcile_skipped audit")
		}
		time.Sleep(time.Millisecond)
	}
	if p.reconcileCalls() != before {
		t.Fatal("reconcile ran against a TAMPERED store")
	}
}
