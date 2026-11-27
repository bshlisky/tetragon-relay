//go:build e3

// Command e3controller is docs/prompts/step-06a-e3-prompt.md's test
// controller driver: a thin wrapper around internal/testcontroller
// (the same package cmd/testcontroller wraps, and internal/
// controlclient's own integration test drives directly) that the E3 CI
// job runs as a separate, long-lived process -- a real relayd process
// managed by systemd is what the Go test suites in this repository
// cannot start by themselves, so this binary, not a `go test` run,
// drives the scenarios that need an agent to actually connect over the
// network.
//
// Gated behind its own build tag, "e3": unlike cmd/testenroll (testca),
// e3controller is purely CI harness code with no identity- or TPM-
// provisioning logic of its own, so it has no reason to share that tag,
// and this keeps "testca" meaning exactly what it already means
// elsewhere (identity test doubles) rather than also covering "is part
// of the E3 test harness."
//
// e3controller self-asserts pass/fail for the one scenario named by
// --mode and exits 0 (pass) or 1 (fail); the E3 CI job's shell checks
// only the exit code (and, for corroborating evidence, greps this
// process's own stdout log), never needing a separate Go test binary.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/testcontroller"
	"google.golang.org/grpc"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "e3controller: FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("e3controller: PASS")
}

type config struct {
	listen             string
	caCertPath         string
	certPath           string
	keyPath            string
	trustDomain        string
	mode               string
	minHeartbeats      int
	heartbeatDeadline  time.Duration
	reconnectAssertFor time.Duration
	overallTimeout     time.Duration
}

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("e3controller", flag.ContinueOnError)
	var c config
	fs.StringVar(&c.listen, "listen", "", "address to listen on (host:port)")
	fs.StringVar(&c.caCertPath, "ca-cert", "", "PEM file: CA certificate agent certificates must chain to (cmd/testenroll's --ca-cert-out)")
	fs.StringVar(&c.certPath, "cert", "", "PEM file: this controller's own server certificate (cmd/testenroll's --controller-cert-out)")
	fs.StringVar(&c.keyPath, "key", "", "PEM file: this controller's own private key (cmd/testenroll's --controller-key-out)")
	fs.StringVar(&c.trustDomain, "trust-domain", "", "SPIFFE trust domain (must match relay.yaml)")
	fs.StringVar(&c.mode, "mode", "steady", "scenario to run: steady (S3/S6: wait for --min-heartbeats) or revoke (S4: send Terminate{REVOKED} after the first connection, then assert no reconnection for --reconnect-assert-for)")
	fs.IntVar(&c.minHeartbeats, "min-heartbeats", 3, "steady mode: number of Heartbeats to wait for before PASS")
	fs.DurationVar(&c.heartbeatDeadline, "heartbeat-deadline", 90*time.Second, "steady mode: overall deadline to observe --min-heartbeats")
	fs.DurationVar(&c.reconnectAssertFor, "reconnect-assert-for", 65*time.Second, "revoke mode: how long to watch for a second connection after sending Terminate{REVOKED} before declaring PASS")
	fs.DurationVar(&c.overallTimeout, "overall-timeout", 150*time.Second, "hard upper bound on this process's own lifetime: if nothing else has reported a result by then (e.g. no connection ever arrived at all, in either mode), FAIL rather than hang forever")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	for name, v := range map[string]string{"listen": c.listen, "ca-cert": c.caCertPath, "cert": c.certPath, "key": c.keyPath, "trust-domain": c.trustDomain} {
		if v == "" {
			return config{}, fmt.Errorf("--%s is required", name)
		}
	}
	if c.mode != "steady" && c.mode != "revoke" {
		return config{}, fmt.Errorf("--mode must be \"steady\" or \"revoke\", got %q", c.mode)
	}
	return c, nil
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	caCert, err := readCertPEM(cfg.caCertPath)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	serverCert, err := tls.LoadX509KeyPair(cfg.certPath, cfg.keyPath)
	if err != nil {
		return fmt.Errorf("load server certificate/key: %w", err)
	}

	resultCh := make(chan error, 1)
	var script testcontroller.Script
	switch cfg.mode {
	case "steady":
		script = steadyScript(cfg, resultCh)
	case "revoke":
		script = revokeScript(cfg, resultCh)
	}

	srv := testcontroller.NewServer(testcontroller.Config{
		TrustDomain: cfg.trustDomain, ServerCertificate: serverCert,
		ClientCABundle: []*x509.Certificate{caCert}, HeartbeatIntervalSeconds: 15,
		Script: script,
	})
	lis, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.listen, err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(srv.Credentials()))
	controlv1.RegisterAgentControlServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	fmt.Printf("e3controller: listening on %s, mode=%s\n", lis.Addr(), cfg.mode)
	select {
	case err := <-resultCh:
		return err
	case <-time.After(cfg.overallTimeout):
		return fmt.Errorf("no result after %s (mode=%s): no connection ever completed Hello/HelloAck, or the script itself never finished", cfg.overallTimeout, cfg.mode)
	}
}

func readCertPEM(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is an operator-supplied flag for this one-shot CI test tool
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s contains no PEM block", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// steadyScript implements S3/S6: wait for cfg.minHeartbeats Heartbeat
// messages (printing each arrival, for the CI job's own log evidence),
// within cfg.heartbeatDeadline; resultCh receives nil on success, an
// error otherwise. Every connection (including a reconnect) resets the
// per-connection heartbeat count to zero and logs the new connection, so
// S6's reconnect-after-watchdog-restart is visible in this process's own
// log even though e3controller itself does not assert on it (the CI
// job's shell does, via systemctl/journalctl).
func steadyScript(cfg config, resultCh chan<- error) testcontroller.Script {
	var connNum int64
	return func(ctx context.Context, stream testcontroller.ScriptStream, hostUUID string) error {
		n := atomic.AddInt64(&connNum, 1)
		fmt.Printf("e3controller: connection #%d from host %s\n", n, hostUUID)
		heartbeats := 0
		deadline := time.Now().Add(cfg.heartbeatDeadline)
		for heartbeats < cfg.minHeartbeats {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				err := fmt.Errorf("steady: only %d/%d heartbeats observed before the %s deadline", heartbeats, cfg.minHeartbeats, cfg.heartbeatDeadline)
				trySend(resultCh, err)
				return err
			}
			msg, err := testcontroller.WaitForAgentMessage(stream, remaining)
			if err != nil {
				trySend(resultCh, err)
				return err
			}
			if msg.GetHeartbeat() == nil {
				continue // ignore anything that is not a Heartbeat (e.g. a StateReport this test never requested)
			}
			heartbeats++
			fmt.Printf("e3controller: heartbeat %d/%d from connection #%d at %s\n", heartbeats, cfg.minHeartbeats, n, time.Now().UTC().Format(time.RFC3339))
		}
		trySend(resultCh, nil)
		// Keep the stream (and this connection's Script call) open so a
		// caller who wants to observe more than cfg.minHeartbeats (e.g.
		// S6, watching for a watchdog-triggered restart and reconnect)
		// can -- resultCh has already been signaled, so the CI job's
		// shell does not wait on this process's exit for that.
		<-ctx.Done()
		return nil
	}
}

// revokeScript implements S4: on the first connection, after observing
// Hello/HelloAck, send Terminate{REVOKED}; then watch for
// cfg.reconnectAssertFor to confirm no SECOND connection (Script
// invocation) ever arrives -- internal/agent.ControlLoop.
// HandleControllerMessage's own Terminate{REVOKED} handling (D2) is
// expected to stop RunSession from reconnecting at all (step-06a-
// resume.md D3).
func revokeScript(cfg config, resultCh chan<- error) testcontroller.Script {
	var connNum int64
	return func(ctx context.Context, stream testcontroller.ScriptStream, hostUUID string) error {
		n := atomic.AddInt64(&connNum, 1)
		fmt.Printf("e3controller: connection #%d from host %s\n", n, hostUUID)
		if n > 1 {
			err := fmt.Errorf("revoke: a second connection arrived (host %s) within %s of Terminate{REVOKED} -- relayd should not have reconnected", hostUUID, cfg.reconnectAssertFor)
			trySend(resultCh, err)
			return err
		}
		seq := testcontroller.NewNextSeqAfterHelloAck()
		if err := testcontroller.SendTerminate(stream, seq, controlv1.Terminate_REVOKED, "e3controller: S4 revoke scenario"); err != nil {
			trySend(resultCh, fmt.Errorf("send Terminate{REVOKED}: %w", err))
			return err
		}
		fmt.Printf("e3controller: sent Terminate{REVOKED} to connection #1; watching for a reconnect for %s\n", cfg.reconnectAssertFor)
		// The window is a timer, independent of this stream: relayd
		// closes the stream right after Terminate{REVOKED}, which cancels
		// ctx, and run 45924877288 showed the old select returning on
		// ctx.Done without ever reporting. trySend is first-wins, so a
		// second connection's error (above) beats this nil.
		time.AfterFunc(cfg.reconnectAssertFor, func() {
			fmt.Printf("e3controller: no reconnect observed within %s\n", cfg.reconnectAssertFor)
			trySend(resultCh, nil)
		})
		<-ctx.Done()
		return nil
	}
}

func trySend(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}
