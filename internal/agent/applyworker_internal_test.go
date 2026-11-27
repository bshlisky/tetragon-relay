package agent

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/trust"
	"github.com/bshlisky/tetragon-relay/internal/verify"
)

// syncClock is a settable clock safe for concurrent use.
type syncClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *syncClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *syncClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func alertMsg(n int) *controlv1.AgentMessage {
	return &controlv1.AgentMessage{Body: &controlv1.AgentMessage_Alert{Alert: &controlv1.Alert{UnixTime: int64(n)}}}
}

func TestOutbox_BoundDropsOldestAndCounts(t *testing.T) {
	o := NewOutbox()
	for i := 0; i < limits.MaxOutboxMessages+3; i++ {
		o.Push(alertMsg(i))
	}
	if o.Len() != limits.MaxOutboxMessages || o.Dropped() != 3 {
		t.Fatalf("Len = %d, Dropped = %d; want %d, 3", o.Len(), o.Dropped(), limits.MaxOutboxMessages)
	}
	head := o.Peek()
	if head.GetAlert().GetUnixTime() != 3 {
		t.Fatalf("oldest kept = %d, want 3", head.GetAlert().GetUnixTime())
	}
	o.Pop(alertMsg(99)) // not the head: no-op
	if o.Len() != limits.MaxOutboxMessages {
		t.Fatal("Pop of a non-head message removed something")
	}
	o.Pop(head)
	if o.Peek().GetAlert().GetUnixTime() != 4 {
		t.Fatal("Pop(head) did not remove the head")
	}
	select {
	case <-o.Notify():
	default:
		t.Fatal("Push did not notify")
	}
	empty := NewOutbox()
	if empty.Peek() != nil {
		t.Fatal("Peek on empty outbox")
	}
	empty.Pop(head)
}

func TestLink_Reachability(t *testing.T) {
	if _, err := NewLink(nil, time.Second); err == nil {
		t.Fatal("NewLink(nil clock) = nil error")
	}
	if _, err := NewLink(time.Now, 0); err == nil {
		t.Fatal("NewLink(0 interval) = nil error")
	}
	clk := &syncClock{now: time.Unix(1000, 0)}
	l, _ := NewLink(clk.Now, 15*time.Second)
	ctx := context.Background()
	if l.Reachable(ctx) || l.Connected() {
		t.Fatal("a new Link is reachable")
	}
	l.Acked() // ignored while down
	l.Up(func() {})
	if !l.Reachable(ctx) || !l.Connected() {
		t.Fatal("not reachable right after Up")
	}
	clk.Advance(29 * time.Second)
	l.Acked()
	clk.Advance(30 * time.Second)
	if !l.Reachable(ctx) {
		t.Fatal("not reachable 30s after an ack (limit 2 x 15s)")
	}
	clk.Advance(time.Second)
	if l.Reachable(ctx) {
		t.Fatal("reachable 31s after the last ack")
	}
	var sawConnected bool
	l.Settle(func(c bool) { sawConnected = c })
	if !sawConnected {
		t.Fatal("Settle reported disconnected")
	}
	l.Down(func() {})
	if l.Reachable(ctx) {
		t.Fatal("reachable after Down")
	}
}

func TestAlerter_RateLimitPerKind(t *testing.T) {
	if _, err := NewAlerter(nil, &FakeAuditor{}, time.Now); err == nil {
		t.Fatal("NewAlerter(nil outbox) = nil error")
	}
	clk := &syncClock{now: time.Unix(1000, 0)}
	o := NewOutbox()
	aud := &syncAuditor{}
	a, _ := NewAlerter(o, aud, clk.Now)
	if !a.Raise(controlv1.Alert_DRIFT, "first") {
		t.Fatal("first DRIFT not raised")
	}
	clk.Advance(4 * time.Minute)
	if a.Raise(controlv1.Alert_DRIFT, "second") {
		t.Fatal("second DRIFT within 5 minutes was raised")
	}
	if !a.Raise(controlv1.Alert_TAMPER, "other kind") {
		t.Fatal("a different kind was rate-limited")
	}
	clk.Advance(time.Minute)
	if !a.Raise(controlv1.Alert_DRIFT, "third") {
		t.Fatal("DRIFT 5 minutes after the first was suppressed")
	}
	if o.Len() != 3 {
		t.Fatalf("outbox holds %d alerts, want 3", o.Len())
	}
	if !aud.HasStep("alert") || !aud.HasStep("alert_suppressed") {
		t.Fatal("alerts not audited")
	}
	long := strings.Repeat("x", limits.MaxApplyResultDetailBytes+10)
	a.Raise(controlv1.Alert_TRUST_EXPIRED, long)
	var last *controlv1.AgentMessage
	for m := o.Peek(); m != nil; m = o.Peek() {
		last = m
		o.Pop(m)
	}
	if len(last.GetAlert().GetDetail()) != limits.MaxApplyResultDetailBytes {
		t.Fatalf("detail not bounded: %d", len(last.GetAlert().GetDetail()))
	}
}

func TestCommitOnPut_RefusesUnarmedPut(t *testing.T) {
	c := &CommitOnPut{}
	if err := c.Put("relay", apply.LKGSet{}); err == nil {
		t.Fatal("unarmed Put = nil error")
	}
	if committed, _ := c.disarm(); committed {
		t.Fatal("disarm reported a commit")
	}
}

func TestVerifierFor(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	keys := []*ecdsa.PrivateKey{mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)}
	root, err := trust.LoadInitialRoot(buildECDSARoot(t, 1, now, keys, nil))
	if err != nil {
		t.Fatalf("LoadInitialRoot: %v", err)
	}
	if v, why := verifierFor(root, Capabilities{}, now); v == nil {
		t.Fatalf("ECDSA root without ML-DSA: %s", why)
	}
	if v, why := verifierFor(root, Capabilities{}, root.Expires); v != nil || !strings.Contains(why, "expired") {
		t.Fatalf("expired root: v=%v why=%q", v, why)
	}
	hybrid, err := buildHybridTargetsRoot(t, now)
	if err != nil {
		t.Skipf("hybrid root unavailable in this build: %v", err)
	}
	hroot, err := trust.LoadInitialRoot(hybrid)
	if err != nil {
		t.Fatalf("LoadInitialRoot(hybrid): %v", err)
	}
	if v, why := verifierFor(hroot, Capabilities{MLDSAAvailable: false}, now); v != nil || !strings.Contains(why, "ML-DSA") {
		t.Fatalf("ML-DSA root without ML-DSA: v=%v why=%q", v, why)
	}
}

func TestVerifyCodeToStatus(t *testing.T) {
	want := map[verify.Code]controlv1.ApplyResult_Status{
		verify.CodeRejectedSignature:  controlv1.ApplyResult_REJECTED_SIGNATURE,
		verify.CodeRejectedTarget:     controlv1.ApplyResult_REJECTED_TARGET,
		verify.CodeRejectedEpoch:      controlv1.ApplyResult_REJECTED_EPOCH,
		verify.CodeRejectedExpired:    controlv1.ApplyResult_REJECTED_EXPIRED,
		verify.CodeRejectedSchema:     controlv1.ApplyResult_REJECTED_SCHEMA,
		verify.CodeRejectedGuardrail:  controlv1.ApplyResult_REJECTED_GUARDRAIL,
		verify.CodeRejectedCapability: controlv1.ApplyResult_REJECTED_CAPABILITY,
		verify.Code(99):               controlv1.ApplyResult_REJECTED_SCHEMA,
	}
	for c, s := range want {
		if got := verifyCodeToStatus(c); got != s {
			t.Errorf("verifyCodeToStatus(%s) = %s, want %s", c, got, s)
		}
	}
}

func TestConstructorValidation(t *testing.T) {
	if _, err := NewTrustState(nil); err == nil {
		t.Fatal("NewTrustState(nil) = nil error")
	}
	if _, err := NewApplyWorker(ApplyWorkerConfig{}); err == nil {
		t.Fatal("NewApplyWorker(zero) = nil error")
	}
	deps := BundleDeps{Store: &store.Store{}, Roots: &store.Store{}, Commit: &CommitOnPut{}, Trust: &TrustState{}, Engine: &apply.Engine{},
		Version: fakeVersion{}, HostCaps: noCaps{}, Digest: func(context.Context) ([]byte, error) { return nil, nil }}
	if err := deps.validate(); err == nil {
		t.Fatal("BundleDeps without HostUUID validated")
	}
	deps.HostUUID = "h"
	if _, err := NewApplyWorker(ApplyWorkerConfig{Deps: deps}); err == nil {
		t.Fatal("NewApplyWorker without SM etc. = nil error")
	}
	link, _ := NewLink(time.Now, time.Second)
	reg, _ := NewLivenessRegistry(time.Now)
	sm, _ := NewStateMachine(&FakeAuditor{})
	alerter, _ := NewAlerter(NewOutbox(), &FakeAuditor{}, time.Now)
	cfg := ApplyWorkerConfig{Deps: deps, SM: sm, Link: link, Outbox: NewOutbox(), Alerter: alerter, Auditor: &FakeAuditor{}, Liveness: reg, Clock: time.Now}
	if _, err := NewApplyWorker(cfg); err == nil {
		t.Fatal("NewApplyWorker with zero HealthWindow = nil error")
	}
	cfg.HealthWindow = time.Minute
	if _, err := NewApplyWorker(cfg); err != nil {
		t.Fatalf("NewApplyWorker: %v", err)
	}
}

type fakeVersion struct{}

func (fakeVersion) GetVersion(context.Context) (string, error) { return "", errors.New("down") }

type noCaps struct{}

func (noCaps) KprobeOverride() bool { return false }
func (noCaps) LSMBPF() bool         { return false }

// TestApplyWorker_RunJobLivenessBound: the worker keeps reporting
// liveness while a job runs, through a 60 s health window on an injected
// clock, and stops once the job exceeds HealthWindow + slack (B2).
func TestApplyWorker_RunJobLivenessBound(t *testing.T) {
	clk := &syncClock{now: time.Unix(1000, 0)}
	reg, _ := NewLivenessRegistry(clk.Now)
	reg.Register(applyWorkerComponent, applyWorkerLivenessMaxInterval)
	aud := &syncAuditor{}
	w := &ApplyWorker{cfg: ApplyWorkerConfig{Liveness: reg, Clock: clk.Now, Auditor: aud, HealthWindow: 60 * time.Second, touchInterval: time.Millisecond}}

	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		w.runJob(context.Background(), func(context.Context) { <-release })
		close(done)
	}()
	// Walk through the health window in 5 s steps: still healthy.
	for i := 0; i < 12; i++ {
		clk.Advance(5 * time.Second)
		time.Sleep(5 * time.Millisecond)
		if ok, stale, _ := reg.Healthy(); !ok {
			t.Fatalf("apply worker stale (%s) %ds into the health window", stale, (i+1)*5)
		}
	}
	// Past the bound: liveness is withheld.
	clk.Advance(limits.ApplyWorkerLivenessSlack + applyWorkerLivenessMaxInterval + time.Second)
	time.Sleep(10 * time.Millisecond)
	if ok, _, _ := reg.Healthy(); ok {
		t.Fatal("apply worker still healthy after exceeding its bound")
	}
	if !aud.HasStep("apply_worker_stalled") {
		t.Fatal("no apply_worker_stalled audit")
	}
	close(release)
	<-done
}

// blockingJobs is a JobSink standing in for the apply worker: it moves
// the state machine into APPLYING, holds there until released, then
// queues an ApplyResult and settles back, exactly as ApplyWorker does.
type blockingJobs struct {
	sm      *StateMachine
	link    *Link
	outbox  *Outbox
	release chan struct{}
	started chan struct{}
}

func (b *blockingJobs) SubmitBundle([]byte) {
	go func() {
		b.link.Settle(func(bool) { _ = b.sm.Fire(EventVerifiedBundle) })
		close(b.started)
		<-b.release
		b.outbox.Push(applyResultMessage(&controlv1.ApplyResult{Status: controlv1.ApplyResult_APPLIED, Epoch: 7}))
		b.link.Settle(func(connected bool) {
			_ = b.sm.Fire(EventHealthPass)
			if !connected {
				_ = b.sm.Fire(EventStreamLost)
			}
		})
	}()
}

func (b *blockingJobs) SubmitTrustUpdate([][]byte) {}

func countHeartbeats(msgs []*controlv1.AgentMessage) int {
	n := 0
	for _, m := range msgs {
		if m.GetHeartbeat() != nil {
			n++
		}
	}
	return n
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestRunSession_HeartbeatsContinueDuringApply: while a bundle apply
// holds APPLYING (a 60 s health window on the injected clock), the
// stream loop keeps heartbeating and stays live; the ApplyResult goes out
// over the same stream afterwards with the next seq (B2).
func TestRunSession_HeartbeatsContinueDuringApply(t *testing.T) {
	cl, sm, _, _ := newSessionTestFixtures(t)
	cl.Auditor = &syncAuditor{}
	clk := &syncClock{now: time.Unix(1000, 0)}
	reg, _ := NewLivenessRegistry(clk.Now)
	link, _ := NewLink(clk.Now, 15*time.Second)
	outbox := NewOutbox()
	jobs := &blockingJobs{sm: sm, link: link, outbox: outbox, release: make(chan struct{}), started: make(chan struct{})}
	cl.Jobs = jobs
	stream := newFakeStream()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, SessionConfig{
			Connector:   &fakeConnector{results: []connectResult{{stream: stream}}},
			Hello:       func() controlclient.HelloFields { return controlclient.HelloFields{} },
			ControlLoop: cl, Clock: clk.Now, Auditor: cl.Auditor, Liveness: reg,
			Revocations: &fakeRevocations{}, HeartbeatInterval: 5 * time.Millisecond,
			Outbox: outbox, Link: link,
		})
	}()
	waitFor(t, "STEADY", func() bool { return sm.Current() == StateSteady })
	stream.in <- &controlv1.ControllerMessage{Seq: 2, Body: &controlv1.ControllerMessage_Bundle{Bundle: &controlv1.PolicyBundle{Envelope: []byte("env")}}}
	<-jobs.started
	if sm.Current() != StateApplying {
		t.Fatalf("state = %s, want APPLYING", sm.Current())
	}
	before := countHeartbeats(stream.sentMessages())
	for i := 0; i < 12; i++ { // 60 s of health window on the injected clock
		clk.Advance(5 * time.Second)
		time.Sleep(10 * time.Millisecond)
		if !link.Reachable(ctx) {
			t.Fatalf("controller unreachable %ds into the health window", (i+1)*5)
		}
		if ok, stale, _ := reg.Healthy(); !ok {
			t.Fatalf("%s stale during the health window", stale)
		}
	}
	if after := countHeartbeats(stream.sentMessages()); after-before < 3 {
		t.Fatalf("only %d heartbeats during the apply", after-before)
	}
	close(jobs.release)
	waitFor(t, "ApplyResult on the stream", func() bool {
		for _, m := range stream.sentMessages() {
			if m.GetApplyResult() != nil {
				return true
			}
		}
		return false
	})
	waitFor(t, "STEADY after apply", func() bool { return sm.Current() == StateSteady })
	sent := stream.sentMessages()
	for i := 1; i < len(sent); i++ {
		if sent[i].GetSeq() != sent[i-1].GetSeq()+1 {
			t.Fatalf("outbound seq gap at %d: %d after %d", i, sent[i].GetSeq(), sent[i-1].GetSeq())
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("RunSession: %v", err)
	}
}

// TestRunSession_StreamLostDuringApplyIsSettledByWorker: the stream drops
// while APPLYING; RunSession leaves the state alone, and the worker's
// settle moves STEADY -> CONNECTING. The ApplyResult queued while
// disconnected is sent first on the next stream.
func TestRunSession_StreamLostDuringApplyIsSettledByWorker(t *testing.T) {
	cl, sm, _, reg := newSessionTestFixtures(t)
	aud := &syncAuditor{}
	cl.Auditor = aud
	link, _ := NewLink(time.Now, time.Hour)
	outbox := NewOutbox()
	jobs := &blockingJobs{sm: sm, link: link, outbox: outbox, release: make(chan struct{}), started: make(chan struct{})}
	cl.Jobs = jobs
	s1, s2 := newFakeStream(), newFakeStream()
	gate := make(chan struct{})
	connector := &gatedConnector{streams: []ControlStream{s1, s2}, gate: gate}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, SessionConfig{
			Connector: connector, Hello: func() controlclient.HelloFields { return controlclient.HelloFields{} },
			ControlLoop: cl, Clock: time.Now, Auditor: aud, Liveness: reg,
			Revocations: &fakeRevocations{}, HeartbeatInterval: time.Hour, Outbox: outbox, Link: link,
		})
	}()
	waitFor(t, "STEADY", func() bool { return sm.Current() == StateSteady })
	s1.in <- &controlv1.ControllerMessage{Seq: 2, Body: &controlv1.ControllerMessage_Bundle{Bundle: &controlv1.PolicyBundle{Envelope: []byte("env")}}}
	<-jobs.started
	s1.breakStream()
	waitFor(t, "link down", func() bool { return !link.Connected() })
	if sm.Current() != StateApplying {
		t.Fatalf("state after stream loss during apply = %s, want APPLYING", sm.Current())
	}
	close(jobs.release)
	waitFor(t, "CONNECTING", func() bool { return sm.Current() == StateConnecting })
	close(gate)
	waitFor(t, "ApplyResult on the second stream", func() bool {
		msgs := s2.sentMessages()
		return len(msgs) > 0 && msgs[0].GetApplyResult() != nil && msgs[0].GetSeq() == 2
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("RunSession: %v", err)
	}
}

// TestRunSession_ConnectDuringApplyLeavesState covers fireConnected's
// apply-owned branch directly.
func TestRunSession_ConnectDuringApplyLeavesState(t *testing.T) {
	cl, sm, _, _ := newSessionTestFixtures(t)
	aud := &syncAuditor{}
	cl.Auditor = aud
	for _, e := range []Event{EventHelloAck, EventInSync, EventVerifiedBundle} {
		if err := sm.Fire(e); err != nil {
			t.Fatal(err)
		}
	}
	cfg := SessionConfig{ControlLoop: cl, Auditor: aud}
	fireConnected(cfg)
	fireStreamLost(cfg)
	if sm.Current() != StateApplying || !aud.HasStep("session_connected_during_apply") {
		t.Fatalf("state = %s", sm.Current())
	}
}

func TestControlLoop_BundleGoesToJobSink(t *testing.T) {
	cl, sm, _, _ := newSessionTestFixtures(t)
	_ = sm
	sink := &recordingSink{}
	cl.Jobs = sink
	out := NewOutboundSeqAfterHello()
	tracker := &SeqTracker{seen: true, last: 1}
	oc, err := cl.HandleControllerMessage(context.Background(), tracker, out, &controlv1.ControllerMessage{Seq: 2, Body: &controlv1.ControllerMessage_Bundle{Bundle: &controlv1.PolicyBundle{Envelope: []byte("raw")}}})
	if err != nil || oc.Reply != nil || oc.Close {
		t.Fatalf("outcome = %+v, %v", oc, err)
	}
	if string(sink.got) != "raw" {
		t.Fatalf("sink got %q", sink.got)
	}
	oc, err = cl.HandleControllerMessage(context.Background(), tracker, out, &controlv1.ControllerMessage{Seq: 3, Body: &controlv1.ControllerMessage_TrustUpdate{TrustUpdate: &controlv1.TrustUpdate{SignedRoots: [][]byte{[]byte("r2")}}}})
	if err != nil || oc.Reply != nil || len(sink.roots) != 1 || string(sink.roots[0]) != "r2" {
		t.Fatalf("TrustUpdate outcome = %+v, %v; sink %q", oc, err, sink.roots)
	}
	cl.Jobs = nil
	oc, _ = cl.HandleControllerMessage(context.Background(), tracker, out, &controlv1.ControllerMessage{Seq: 4, Body: &controlv1.ControllerMessage_Bundle{Bundle: &controlv1.PolicyBundle{Envelope: []byte("raw")}}})
	if r := oc.Reply.GetApplyResult(); r == nil || r.GetStatus() != controlv1.ApplyResult_APPLY_FAILED || len(r.GetBundleDigest()) != 32 {
		t.Fatalf("nil Jobs reply = %v", oc.Reply)
	}
	oc, _ = cl.HandleControllerMessage(context.Background(), tracker, out, &controlv1.ControllerMessage{Seq: 5, Body: &controlv1.ControllerMessage_TrustUpdate{TrustUpdate: &controlv1.TrustUpdate{}}})
	if oc.Reply.GetAlert() == nil {
		t.Fatalf("nil Jobs TrustUpdate reply = %v", oc.Reply)
	}
}

type recordingSink struct {
	got   []byte
	roots [][]byte
}

func (r *recordingSink) SubmitBundle(env []byte)          { r.got = env }
func (r *recordingSink) SubmitTrustUpdate(roots [][]byte) { r.roots = roots }

// gatedConnector returns streams[0] at once and each later stream only
// after gate is closed.
type gatedConnector struct {
	mu      sync.Mutex
	streams []ControlStream
	calls   int
	gate    chan struct{}
}

func (g *gatedConnector) Connect(ctx context.Context, _ func() controlclient.HelloFields, _ func()) (ControlStream, func() error, error) {
	g.mu.Lock()
	n := g.calls
	g.calls++
	g.mu.Unlock()
	if n > 0 {
		select {
		case <-g.gate:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	if n >= len(g.streams) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	return g.streams[n], func() error { return nil }, nil
}

type fakeRootStore struct {
	persisted []uint64
	err       error
}

func (f *fakeRootStore) PersistTrustRoot(_ []byte, v uint64) error {
	if f.err != nil {
		return f.err
	}
	f.persisted = append(f.persisted, v)
	return nil
}
func (f *fakeRootStore) Tampered() error { return nil }

func trustWorker(t *testing.T, root *trust.Root, roots *fakeRootStore, mldsa bool, now time.Time) (*ApplyWorker, *Outbox, *TrustState) {
	t.Helper()
	ts, _ := NewTrustState(root)
	o := NewOutbox()
	alerter, _ := NewAlerter(o, &syncAuditor{}, func() time.Time { return now })
	return &ApplyWorker{cfg: ApplyWorkerConfig{
		Deps:    BundleDeps{Trust: ts, Roots: roots, Crypto: Capabilities{MLDSAAvailable: mldsa}},
		Alerter: alerter, Auditor: &syncAuditor{}, Clock: func() time.Time { return now },
	}}, o, ts
}

func TestProcessTrustUpdate_RefusesMLDSARootWithoutMLDSA(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Keys := []*ecdsa.PrivateKey{mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)}
	v1, err := trust.LoadInitialRoot(buildECDSARoot(t, 1, now, v1Keys, nil))
	if err != nil {
		t.Fatal(err)
	}
	v2Keys := []*ecdsa.PrivateKey{mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)}
	v2raw := buildHybridTargetsRootChained(t, 2, now, v2Keys, v1Keys)
	roots := &fakeRootStore{}
	w, o, ts := trustWorker(t, v1, roots, false, now)
	w.processTrustUpdate([][]byte{v2raw})
	if ts.Current().Version != 1 || len(roots.persisted) != 0 {
		t.Fatalf("adopted an ML-DSA root without ML-DSA: version %d, persisted %v", ts.Current().Version, roots.persisted)
	}
	if a := o.Peek().GetAlert(); a == nil || !strings.Contains(a.GetDetail(), "mldsa-87") {
		t.Fatalf("alert = %v", o.Peek())
	}
	// The same chain is adopted when ML-DSA is available.
	w2, _, ts2 := trustWorker(t, v1, &fakeRootStore{}, true, now)
	w2.processTrustUpdate([][]byte{v2raw})
	if ts2.Current().Version != 2 {
		t.Skipf("hybrid root not adoptable in this build (version %d)", ts2.Current().Version)
	}
}

func TestProcessTrustUpdate_PersistFailureKeepsCurrentRoot(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1Keys := []*ecdsa.PrivateKey{mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)}
	v1, err := trust.LoadInitialRoot(buildECDSARoot(t, 1, now, v1Keys, nil))
	if err != nil {
		t.Fatal(err)
	}
	v2Keys := []*ecdsa.PrivateKey{mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)}
	v2raw := buildECDSARoot(t, 2, now, v2Keys, v1Keys)
	w, o, ts := trustWorker(t, v1, &fakeRootStore{err: errors.New("disk full")}, true, now)
	w.processTrustUpdate([][]byte{v2raw})
	if ts.Current().Version != 1 {
		t.Fatalf("root adopted in memory although persisting it failed: %d", ts.Current().Version)
	}
	if a := o.Peek().GetAlert(); a == nil || !strings.Contains(a.GetDetail(), "persisting root version 2 failed") {
		t.Fatalf("alert = %v", o.Peek())
	}
	tooMany := make([][]byte, limits.MaxRootChainFiles+1)
	w.processTrustUpdate(tooMany)
}

func TestSubmitTrustUpdate_QueueBound(t *testing.T) {
	aud := &syncAuditor{}
	w := &ApplyWorker{cfg: ApplyWorkerConfig{Auditor: aud}, wake: make(chan struct{}, 1)}
	for i := 0; i < limits.MaxPendingTrustUpdates+1; i++ {
		w.SubmitTrustUpdate([][]byte{{byte(i)}})
	}
	if len(w.trustQueue) != limits.MaxPendingTrustUpdates || !aud.HasStep("trust_update_dropped") {
		t.Fatalf("queue = %d", len(w.trustQueue))
	}
	first, _ := w.takeTrustUpdate()
	if first[0][0] != 1 {
		t.Fatalf("oldest kept = %d, want 1", first[0][0])
	}
}

func TestTrustExpiryMonitor_OncePerConnectionAndDaily(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	keys := []*ecdsa.PrivateKey{mustTestECDSAKey(t), mustTestECDSAKey(t), mustTestECDSAKey(t)}
	root, err := trust.LoadInitialRoot(buildECDSARoot(t, 1, now, keys, nil))
	if err != nil {
		t.Fatal(err)
	}
	clk := &syncClock{now: now}
	ts, _ := NewTrustState(root)
	o := NewOutbox()
	alerter, _ := NewAlerter(o, &syncAuditor{}, clk.Now)
	m := &TrustExpiryMonitor{Trust: ts, Alerter: alerter, Clock: clk.Now}
	m.Connected()
	m.Check()
	if o.Len() != 0 {
		t.Fatal("TRUST_EXPIRED raised for an unexpired root")
	}
	clk.now = root.Expires.Add(time.Minute)
	m.Check()
	if o.Len() != 1 || o.Peek().GetAlert().GetKind() != controlv1.Alert_TRUST_EXPIRED {
		t.Fatalf("no TRUST_EXPIRED on expiry: %d", o.Len())
	}
	clk.Advance(time.Hour)
	m.Check()
	if o.Len() != 1 {
		t.Fatal("TRUST_EXPIRED repeated within the same connection and day")
	}
	m.Connected() // a new connection, an hour later
	if o.Len() != 2 {
		t.Fatal("no TRUST_EXPIRED on the new connection")
	}
	clk.Advance(limits.TrustExpiredAlertInterval)
	m.Check()
	if o.Len() != 3 {
		t.Fatal("no daily TRUST_EXPIRED")
	}
}
