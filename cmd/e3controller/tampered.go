//go:build e3

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/testcontroller"
)

// tamperedScript implements --mode tampered (step 7a S13, ADR 0038). On
// the first connection it requires, in order:
//  1. the first AgentMessage after HelloAck is Alert{TAMPER};
//  2. --min-heartbeats heartbeats, each with an EMPTY epochs map;
//  3. each --bundle is answered REJECTED_TAMPERED (its --expect must say
//     so) with epoch 0;
//  4. if --trust-update is set, one TrustUpdate raises
//     Alert{TRUST_UPDATE_REJECTED}.
func tamperedScript(cfg config, resultCh chan<- error) testcontroller.Script {
	var connNum int64
	return func(ctx context.Context, stream testcontroller.ScriptStream, hostUUID string) error {
		n := atomic.AddInt64(&connNum, 1)
		fmt.Printf("e3controller: [%s] connection #%d from host %s\n", stamp(), n, hostUUID)
		msgs, errs := reader(stream)
		if n > 1 {
			drain(ctx, n, msgs, errs)
			return nil
		}
		err := runTampered(ctx, cfg, n, stream, msgs, errs)
		trySend(resultCh, err)
		if err == nil {
			drain(ctx, n, msgs, errs)
		}
		return err
	}
}

func runTampered(ctx context.Context, cfg config, n int64, stream testcontroller.ScriptStream, msgs <-chan *controlv1.AgentMessage, errs <-chan error) error {
	next := func(what string, timeout time.Duration) (*controlv1.AgentMessage, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-errs:
			return nil, fmt.Errorf("stream ended waiting for %s: %w", what, err)
		case <-time.After(timeout):
			return nil, fmt.Errorf("no %s within %s", what, timeout)
		case m := <-msgs:
			logAgentMessage(n, m)
			return m, nil
		}
	}
	first, err := next("the first message", 30*time.Second)
	if err != nil {
		return err
	}
	if first.GetAlert().GetKind() != controlv1.Alert_TAMPER {
		return fmt.Errorf("first message after HelloAck is %v, want Alert{TAMPER}", first)
	}
	fmt.Println("e3controller: Alert TAMPER OK (first message after HelloAck)")
	for hb := 0; hb < cfg.minHeartbeats; {
		m, err := next("a heartbeat", 40*time.Second)
		if err != nil {
			return err
		}
		h := m.GetHeartbeat()
		if h == nil {
			continue
		}
		if len(h.GetEpochs()) != 0 {
			return fmt.Errorf("heartbeat epochs = %v, want an empty map in tampered mode", h.GetEpochs())
		}
		if len(h.GetLoadedDigest()) != sha256.Size {
			return fmt.Errorf("heartbeat loaded_digest is %d bytes, want a live digest", len(h.GetLoadedDigest()))
		}
		hb++
		fmt.Printf("e3controller: tampered heartbeat %d/%d OK (empty epochs, loaded_digest %x)\n", hb, cfg.minHeartbeats, h.GetLoadedDigest())
	}
	seq := testcontroller.NewNextSeqAfterHelloAck()
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
		for {
			m, err := next("the ApplyResult", cfg.applyTimeout)
			if err != nil {
				return err
			}
			r := m.GetApplyResult()
			if r == nil || !bytes.Equal(r.GetBundleDigest(), want[:]) {
				continue
			}
			if r.GetStatus().String() != cfg.expects[i] || r.GetEpoch() != 0 {
				return fmt.Errorf("bundle %d: ApplyResult status %s epoch %d, want %s epoch 0", i+1, r.GetStatus(), r.GetEpoch(), cfg.expects[i])
			}
			fmt.Printf("e3controller: bundle %d OK: %s\n", i+1, r.GetStatus())
			break
		}
	}
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
		for {
			m, err := next("Alert TRUST_UPDATE_REJECTED", cfg.alertTimeout)
			if err != nil {
				return err
			}
			if m.GetAlert().GetKind() == controlv1.Alert_TRUST_UPDATE_REJECTED {
				fmt.Println("e3controller: Alert TRUST_UPDATE_REJECTED OK")
				break
			}
		}
	}
	return nil
}
