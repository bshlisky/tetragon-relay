//go:build e3

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/testcontroller"
)

// listFlag collects a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// reader runs the stream's only Recv loop (testcontroller.WaitForAgentMessage
// leaves a Recv goroutine behind on timeout, which would swallow the next
// message) and delivers every AgentMessage on msgs.
func reader(stream testcontroller.ScriptStream) (<-chan *controlv1.AgentMessage, <-chan error) {
	msgs := make(chan *controlv1.AgentMessage, 64)
	errs := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				errs <- err
				return
			}
			msgs <- m
		}
	}()
	return msgs, errs
}

func stamp() string { return time.Now().UTC().Format(time.RFC3339) }

// logAgentMessage prints the evidence line for one agent message.
func logAgentMessage(conn int64, m *controlv1.AgentMessage) {
	switch b := m.GetBody().(type) {
	case *controlv1.AgentMessage_Heartbeat:
		fmt.Printf("e3controller: [%s] conn #%d seq=%d heartbeat epochs=%v loaded_digest=%x telemetry_last_seq=%d telemetry_backlog=%d\n", stamp(), conn, m.GetSeq(), b.Heartbeat.GetEpochs(), b.Heartbeat.GetLoadedDigest(), b.Heartbeat.GetTelemetryLastSeq(), b.Heartbeat.GetTelemetryBacklog())
	case *controlv1.AgentMessage_ApplyResult:
		r := b.ApplyResult
		fmt.Printf("e3controller: [%s] conn #%d seq=%d ApplyResult status=%s epoch=%d bundle_digest=%x loaded_digest_after=%x detail=%q\n", stamp(), conn, m.GetSeq(), r.GetStatus(), r.GetEpoch(), r.GetBundleDigest(), r.GetLoadedDigestAfter(), r.GetDetail())
	case *controlv1.AgentMessage_Alert:
		fmt.Printf("e3controller: [%s] conn #%d seq=%d Alert kind=%s detail=%q\n", stamp(), conn, m.GetSeq(), b.Alert.GetKind(), b.Alert.GetDetail())
	case *controlv1.AgentMessage_StateReport:
		fmt.Printf("e3controller: [%s] conn #%d seq=%d StateReport epochs=%v loaded_digest=%x policies=%d\n", stamp(), conn, m.GetSeq(), b.StateReport.GetEpochs(), b.StateReport.GetLoadedDigest(), len(b.StateReport.GetPolicies()))
	default:
		fmt.Printf("e3controller: [%s] conn #%d seq=%d %T\n", stamp(), conn, m.GetSeq(), b)
	}
}

// bundlesScript implements --mode bundles (step 6b S7-S12): on the first
// connection, optionally send one TrustUpdate (--trust-update files, in
// order), then each --bundle in turn, waiting for its ApplyResult and
// checking it against the matching --expect status and the bundle's
// digest. While waiting it counts heartbeats (--min-heartbeats-during-apply
// per bundle). Then, if --expect-alert is set, it waits for an Alert of
// that kind. Any later connection is only logged.
func bundlesScript(cfg config, resultCh chan<- error) testcontroller.Script {
	var connNum int64
	return func(ctx context.Context, stream testcontroller.ScriptStream, hostUUID string) error {
		n := atomic.AddInt64(&connNum, 1)
		fmt.Printf("e3controller: [%s] connection #%d from host %s\n", stamp(), n, hostUUID)
		msgs, errs := reader(stream)
		if n > 1 {
			drain(ctx, n, msgs, errs)
			return nil
		}
		err := runBundles(ctx, cfg, n, stream, msgs, errs)
		trySend(resultCh, err)
		if err == nil {
			drain(ctx, n, msgs, errs)
		}
		return err
	}
}

func drain(ctx context.Context, n int64, msgs <-chan *controlv1.AgentMessage, errs <-chan error) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-errs:
			return
		case m := <-msgs:
			logAgentMessage(n, m)
		}
	}
}

func runBundles(ctx context.Context, cfg config, n int64, stream testcontroller.ScriptStream, msgs <-chan *controlv1.AgentMessage, errs <-chan error) error {
	seq := testcontroller.NewNextSeqAfterHelloAck()
	if len(cfg.trustUpdates) > 0 {
		var roots [][]byte
		for _, p := range cfg.trustUpdates {
			raw, err := os.ReadFile(p) //nolint:gosec // G304: operator-supplied flag for this CI tool
			if err != nil {
				return err
			}
			roots = append(roots, raw)
		}
		if err := stream.Send(&controlv1.ControllerMessage{Seq: seq.Next(), Body: &controlv1.ControllerMessage_TrustUpdate{TrustUpdate: &controlv1.TrustUpdate{SignedRoots: roots}}}); err != nil {
			return fmt.Errorf("send TrustUpdate: %w", err)
		}
		fmt.Printf("e3controller: [%s] sent TrustUpdate with %d root(s)\n", stamp(), len(roots))
	}
	for i, path := range cfg.bundles {
		env, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied flag for this CI tool
		if err != nil {
			return err
		}
		want := sha256.Sum256(env)
		if err := stream.Send(&controlv1.ControllerMessage{Seq: seq.Next(), Body: &controlv1.ControllerMessage_Bundle{Bundle: &controlv1.PolicyBundle{Envelope: env}}}); err != nil {
			return fmt.Errorf("send bundle %s: %w", path, err)
		}
		fmt.Printf("e3controller: [%s] sent bundle %d (%s, digest %x)\n", stamp(), i+1, path, want)
		heartbeats := 0
		deadline := time.After(cfg.applyTimeout)
		var res *controlv1.ApplyResult
		for res == nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-errs:
				return fmt.Errorf("stream ended waiting for bundle %d's ApplyResult: %w", i+1, err)
			case <-deadline:
				return fmt.Errorf("no ApplyResult for bundle %d within %s", i+1, cfg.applyTimeout)
			case m := <-msgs:
				logAgentMessage(n, m)
				if m.GetHeartbeat() != nil {
					heartbeats++
				}
				if r := m.GetApplyResult(); r != nil && bytes.Equal(r.GetBundleDigest(), want[:]) {
					res = r
				}
			}
		}
		if got := res.GetStatus().String(); got != cfg.expects[i] {
			return fmt.Errorf("bundle %d: ApplyResult status %s, want %s (detail %q)", i+1, got, cfg.expects[i], res.GetDetail())
		}
		if heartbeats < cfg.minHeartbeatsDuringApply {
			return fmt.Errorf("bundle %d: only %d heartbeats while waiting for its ApplyResult, want >= %d", i+1, heartbeats, cfg.minHeartbeatsDuringApply)
		}
		fmt.Printf("e3controller: bundle %d OK: %s (%d heartbeats while waiting)\n", i+1, res.GetStatus(), heartbeats)
	}
	if cfg.expectAlert != "" {
		deadline := time.After(cfg.alertTimeout)
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-errs:
				return fmt.Errorf("stream ended waiting for Alert %s: %w", cfg.expectAlert, err)
			case <-deadline:
				return fmt.Errorf("no Alert %s within %s", cfg.expectAlert, cfg.alertTimeout)
			case m := <-msgs:
				logAgentMessage(n, m)
				if a := m.GetAlert(); a != nil && a.GetKind().String() == cfg.expectAlert {
					fmt.Printf("e3controller: Alert %s OK\n", cfg.expectAlert)
					return nil
				}
			}
		}
	}
	return nil
}

// stateScript implements --mode state: send a StateRequest and check the
// StateReport's epoch for each --expect-epoch scope=N.
func stateScript(cfg config, resultCh chan<- error) testcontroller.Script {
	var connNum int64
	return func(ctx context.Context, stream testcontroller.ScriptStream, hostUUID string) error {
		n := atomic.AddInt64(&connNum, 1)
		fmt.Printf("e3controller: [%s] connection #%d from host %s\n", stamp(), n, hostUUID)
		msgs, errs := reader(stream)
		err := func() error {
			if err := testcontroller.SendStateRequest(stream, testcontroller.NewNextSeqAfterHelloAck(), []byte("e3-state")); err != nil {
				return err
			}
			deadline := time.After(30 * time.Second)
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case err := <-errs:
					return err
				case <-deadline:
					return fmt.Errorf("no StateReport within 30s")
				case m := <-msgs:
					logAgentMessage(n, m)
					rep := m.GetStateReport()
					if rep == nil {
						continue
					}
					for _, e := range cfg.expectEpochs {
						scope, v, _ := strings.Cut(e, "=")
						want, perr := strconv.ParseUint(v, 10, 64)
						if perr != nil {
							return fmt.Errorf("--expect-epoch %q: %w", e, perr)
						}
						if got := rep.GetEpochs()[scope]; got != want {
							return fmt.Errorf("StateReport epoch for %q = %d, want %d", scope, got, want)
						}
					}
					fmt.Printf("e3controller: StateReport epochs OK: %v\n", rep.GetEpochs())
					return nil
				}
			}
		}()
		trySend(resultCh, err)
		<-ctx.Done()
		return err
	}
}
