package controlclient

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// dialOptions builds the grpc.DialOptions every Dial call uses: mTLS
// transport credentials (BuildTLSConfig), HTTP/2 keepalive PING
// (architecture doc 6.1: every 30 s, 10 s timeout), and the client-side
// message size caps (6.1: "Max frame 1 MiB").
func dialOptions(cfg Config) ([]grpc.DialOption, error) {
	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	return []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                limits.ControlKeepaliveInterval,
			Timeout:             limits.ControlKeepaliveTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(limits.MaxControlMessageBytes),
			grpc.MaxCallSendMsgSize(limits.MaxControlMessageBytes),
		),
	}, nil
}

// Dial connects to one of cfg.Endpoints (architecture doc 6.3 step 1: a
// pinned IP:port list, never DNS), using "passthrough:///" targets so
// grpc-go's default DNS resolver is never invoked. On failure across every
// configured endpoint, it retries the whole list after a full-jitter
// exponential backoff delay (DialBackoff: 1 s base, 5 min cap,
// architecture doc 6.3 step 6), until ctx is done or an endpoint becomes
// ready.
//
// Dial implements only connection establishment; the full control message
// loop, heartbeats and bundle handling are step 6 (docs/prompts/
// step-05b.md Part C2/Out of scope).
func Dial(ctx context.Context, cfg Config) (*grpc.ClientConn, error) {
	opts, err := dialOptions(cfg)
	if err != nil {
		return nil, err
	}
	attempt := 0
	for {
		for _, ep := range cfg.Endpoints {
			conn, err := dialOneEndpoint(ctx, ep, opts)
			if err == nil {
				return conn, nil
			}
		}
		delay := DialBackoff(attempt, rand.Float64()) //nolint:gosec // G404: reconnect jitter, not security-sensitive
		attempt++
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %w", ErrDialCanceled, ctx.Err())
		}
	}
}

// dialOneEndpoint creates a client for ep and waits for it to become
// Ready, or returns an error if ctx is done or the connection enters a
// terminal/transient state first. It never resolves ep via DNS
// ("passthrough:///" bypasses grpc-go's default resolver entirely).
func dialOneEndpoint(ctx context.Context, ep string, opts []grpc.DialOption) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient("passthrough:///"+ep, opts...)
	if err != nil {
		return nil, fmt.Errorf("controlclient: create client for %s: %w", ep, err)
	}
	conn.Connect()
	if !waitReady(ctx, conn) {
		_ = conn.Close()
		return nil, fmt.Errorf("controlclient: %s did not become ready", ep)
	}
	return conn, nil
}

func waitReady(ctx context.Context, conn *grpc.ClientConn) bool {
	for {
		s := conn.GetState()
		if s == connectivity.Ready {
			return true
		}
		if s == connectivity.Shutdown {
			return false
		}
		if !conn.WaitForStateChange(ctx, s) {
			return false
		}
	}
}

// AgentControlClient returns the generated gRPC client stub for conn, so
// callers can open the Connect bidi stream.
func AgentControlClient(conn *grpc.ClientConn) controlv1.AgentControlClient {
	return controlv1.NewAgentControlClient(conn)
}
