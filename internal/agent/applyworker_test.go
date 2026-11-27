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
	rootEnv, _, targetsKey := standardRootWithTargetsKey(t, 1, now.Add(300*24*time.Hour))
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
	outbox := agent.NewOutbox()
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
			Store: st, Commit: commit, Trust: ts, Engine: engine, Version: fixedVersion{"v1.8.0"},
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
	return &pipeline{t: t, now: now, st: st, dir: dir, sm: sm, link: link, outbox: outbox, engine: engine, auditor: auditor, worker: w, targets: targetsKey, liveness: liveness}
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
	if r.GetStatus() != controlv1.ApplyResult_REJECTED_EPOCH || !strings.Contains(r.GetDetail(), "TAMPERED") {
		t.Fatalf("tampered: %v", r)
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
	if r.GetStatus() != controlv1.ApplyResult_REJECTED_EPOCH || r.GetDetail() != "superseded" || string(r.GetBundleDigest()) != string(digestOf(superseded)) {
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
	if r := p.nextResult(); r.GetStatus() != controlv1.ApplyResult_APPLY_FAILED || !strings.Contains(r.GetDetail(), "DEGRADED") {
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
		{"rollback failed", apply.StatusRollbackFailed, false, controlv1.ApplyResult_APPLY_FAILED, agent.StateDegraded, true},
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
			var gotAlert bool
			var r *controlv1.ApplyResult
			for r == nil {
				m := p.next()
				if a := m.GetAlert(); a != nil && a.GetKind() == controlv1.Alert_DRIFT {
					gotAlert = true
				}
				r = m.GetApplyResult()
			}
			if r.GetStatus() != c.want {
				t.Fatalf("status = %s, want %s (%s)", r.GetStatus(), c.want, r.GetDetail())
			}
			if c.wantAlert && !gotAlert {
				// The alert is pushed after the result.
				if a := p.next().GetAlert(); a == nil || a.GetKind() != controlv1.Alert_DRIFT {
					t.Fatalf("no DRIFT alert for ROLLBACK_FAILED")
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
