package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/store"
)

// fakeRevocations records MarkRevoked calls; err, if set, is returned.
type fakeRevocations struct {
	mu      sync.Mutex
	marks   []string
	err     error
	present bool
	readErr error
}

func (f *fakeRevocations) MarkRevoked(_ time.Time, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.marks = append(f.marks, reason)
	return nil
}

func (f *fakeRevocations) Revocation() (store.Revocation, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return store.Revocation{At: time.Unix(1, 0), Reason: "REVOKED: test"}, f.present, f.readErr
}

// syncAuditor is a FakeAuditor safe to read while RunSession writes.
type syncAuditor struct {
	mu    sync.Mutex
	steps []string
}

func (a *syncAuditor) Record(e AuditEvent) {
	a.mu.Lock()
	a.steps = append(a.steps, e.Step)
	a.mu.Unlock()
}

func (a *syncAuditor) HasStep(step string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.steps {
		if s == step {
			return true
		}
	}
	return false
}

func openAgentTestStore(t *testing.T, dir string, sealer *store.FakeKeySealer, counter *store.FakeMonotonicCounter) *store.Store {
	t.Helper()
	s, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return s
}

func sessionWith(cl *ControlLoop, reg *LivenessRegistry, conn Connector, rev RevocationRecorder) SessionConfig {
	return SessionConfig{
		Connector:         conn,
		Hello:             func() controlclient.HelloFields { return controlclient.HelloFields{} },
		ControlLoop:       cl,
		Clock:             func() time.Time { return time.Unix(1700000000, 0) },
		Auditor:           cl.Auditor,
		Liveness:          reg,
		Revocations:       rev,
		HeartbeatInterval: time.Hour,
		touchInterval:     time.Millisecond,
	}
}

func waitState(t *testing.T, sm *StateMachine, want State) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for sm.Current() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sm.Current() != want {
		t.Fatalf("state = %s, want %s", sm.Current(), want)
	}
}

// TestRevocation_RevokeRestartStaysRevokedAndNeverDials: D2. Revoke
// through a real store, "restart" (reopen the store, fresh state
// machine and session), and the agent comes back REVOKED, parked, and
// never calls Connect.
func TestRevocation_RevokeRestartStaysRevokedAndNeverDials(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sealer := &store.FakeKeySealer{Key: []byte("test-hmac-key-0123456789abcdef")}
	counter := store.NewFakeMonotonicCounter()

	// First process: connect, receive Terminate{REVOKED}.
	st := openAgentTestStore(t, dir, sealer, counter)
	cl, sm, _, reg := newSessionTestFixtures(t)
	stream := newFakeStream()
	conn1 := &fakeConnector{results: []connectResult{{stream: stream}}}
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { done1 <- RunSession(ctx1, sessionWith(cl, reg, conn1, st)) }()
	waitState(t, sm, StateSteady)
	stream.in <- &controlv1.ControllerMessage{Seq: 2, Body: &controlv1.ControllerMessage_Terminate{
		Terminate: &controlv1.Terminate{Reason: controlv1.Terminate_REVOKED, Detail: "host decommissioned"},
	}}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok, _ := st.Revocation(); ok || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel1()
	if err := <-done1; err != nil {
		t.Fatalf("first RunSession: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Second process.
	st2 := openAgentTestStore(t, dir, sealer, counter)
	defer func() { _ = st2.Close() }()
	r, ok, err := st2.Revocation()
	if err != nil || !ok || r.Reason != "REVOKED: host decommissioned" {
		t.Fatalf("persisted marker = %+v, %v, %v", r, ok, err)
	}
	cl2, sm2, auditor2, reg2 := newSessionTestFixtures(t)
	restored, err := RestoreRevocation(sm2, st2, auditor2)
	if err != nil || !restored {
		t.Fatalf("RestoreRevocation = %v, %v; want true, nil", restored, err)
	}
	if sm2.Current() != StateRevoked {
		t.Fatalf("state after restore = %s, want REVOKED", sm2.Current())
	}
	conn2 := &fakeConnector{}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- RunSession(ctx2, sessionWith(cl2, reg2, conn2, st2)) }()
	time.Sleep(100 * time.Millisecond)
	conn2.mu.Lock()
	calls := conn2.calls
	conn2.mu.Unlock()
	if calls != 0 {
		t.Fatalf("Connect called %d times after a persisted revocation, want 0", calls)
	}
	if healthy, stale, _ := reg2.Healthy(); !healthy {
		t.Fatalf("liveness unhealthy while parked: %q", stale)
	}
	cancel2()
	if err := <-done2; err != nil {
		t.Fatalf("second RunSession: %v", err)
	}
}

func TestRevocation_PersistFailureIsAuditedAndStillParks(t *testing.T) {
	cl, sm, _, reg := newSessionTestFixtures(t)
	stream := newFakeStream()
	conn := &fakeConnector{results: []connectResult{{stream: stream}}}
	rev := &fakeRevocations{err: errors.New("disk full")}
	auditor := &syncAuditor{}
	cfg := sessionWith(cl, reg, conn, rev)
	cfg.Auditor = auditor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunSession(ctx, cfg) }()
	waitState(t, sm, StateSteady)
	stream.in <- &controlv1.ControllerMessage{Seq: 2, Body: &controlv1.ControllerMessage_Terminate{
		Terminate: &controlv1.Terminate{Reason: controlv1.Terminate_REVOKED},
	}}
	deadline := time.Now().Add(2 * time.Second)
	for !auditor.HasStep("revocation_persist_failed") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !auditor.HasStep("revocation_persist_failed") {
		t.Fatal("no revocation_persist_failed audit record")
	}
	select {
	case err := <-done:
		t.Fatalf("RunSession returned (%v); want parked", err)
	case <-time.After(50 * time.Millisecond):
	}
	conn.mu.Lock()
	calls := conn.calls
	conn.mu.Unlock()
	if calls != 1 {
		t.Fatalf("Connect calls = %d, want 1", calls)
	}
}

func TestRestoreRevocation_NotRevokedAndReadError(t *testing.T) {
	_, sm, auditor, _ := newSessionTestFixtures(t)
	restored, err := RestoreRevocation(sm, &fakeRevocations{}, auditor)
	if err != nil || restored || sm.Current() != StateConnecting {
		t.Fatalf("no marker: restored=%v err=%v state=%s", restored, err, sm.Current())
	}
	restored, err = RestoreRevocation(sm, &fakeRevocations{readErr: store.ErrTampered}, auditor)
	if !errors.Is(err, store.ErrTampered) || restored {
		t.Fatalf("read error: restored=%v err=%v, want the error", restored, err)
	}
}

func TestTruncateUTF8(t *testing.T) {
	if got := truncateUTF8("short", 10); got != "short" {
		t.Fatalf("got %q", got)
	}
	s := strings.Repeat("a", limits.MaxRevokedReasonBytes-1) + "é" // é is 2 bytes; would split
	got := truncateUTF8(s, limits.MaxRevokedReasonBytes)
	if len(got) != limits.MaxRevokedReasonBytes-1 || !strings.HasSuffix(got, "a") {
		t.Fatalf("truncateUTF8 split a rune or kept too much: len %d", len(got))
	}
}
