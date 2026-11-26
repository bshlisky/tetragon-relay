package agent

import (
	"context"
	"math/rand"
	"time"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// ControlStream is the subset of controlv1.AgentControl_ConnectClient
// RunSession needs, so it can be driven against a fake in tests without
// a real gRPC connection. *grpc.BidiStreamingClient[...] (the generated
// type's underlying implementation) satisfies this directly.
type ControlStream interface {
	Send(*controlv1.AgentMessage) error
	Recv() (*controlv1.ControllerMessage, error)
	CloseSend() error
}

// Connector produces one open, Hello/HelloAck-completed control stream
// per Connect call (architecture doc 6.3 steps 1-3), blocking -- with
// its own backoff across both ordinary connectivity failures and
// Hello-level rejections -- until it succeeds or ctx is done. RunSession
// calls Connect exactly once per reconnect cycle; a Connector
// implementation must not return early on a transient failure (that
// would push backoff/retry bookkeeping onto RunSession, which has no way
// to tell a connectivity failure from a Hello rejection without this
// interface's help).
//
// touch is called periodically while Connect is blocked waiting
// (step-06a-resume.md R6A-1: "Blocking waits... count as progress only
// if the component reports before and after them... or have them report
// while waiting"); it must be safe to call from any goroutine.
type Connector interface {
	Connect(ctx context.Context, hello func() controlclient.HelloFields, touch func()) (stream ControlStream, closeStream func() error, err error)
}

// sessionLivenessTouchInterval bounds how long RunSession and its
// Connector ever go without reporting progress while blocked waiting on
// something (a backoff sleep, a Recv with nothing to read): shorter than
// sessionLivenessMaxInterval with headroom, so ordinary scheduling
// jitter never itself causes a false "stalled" report. A package-level
// var (not a const), purely as a test seam -- the same pattern internal/
// hostprobe's bootIDPath and internal/config's lookupGroupGID already
// use -- so a test can shrink it to observe a touch during a
// deliberately short wait without needing to actually wait 5 real
// seconds.
var sessionLivenessTouchInterval = 5 * time.Second

// RealConnector is Connector's production implementation: controlclient.
// Dial (which already retries across endpoints with full-jitter backoff
// internally, architecture doc 6.3 step 6, until ctx is done or a
// connection becomes ready) plus the Connect RPC and Hello/HelloAck. A
// Hello-level failure (the transport connected but the application
// handshake was refused, e.g. a revoked/denylisted identity) is NOT
// something Dial's own backoff covers, since Dial only sees a healthy
// TLS connection; RealConnector applies the SAME DialBackoff function to
// that case too, so a persistently-rejected identity cannot hot-loop
// reconnecting at the TCP level.
type RealConnector struct {
	// Config is controlclient.Config minus ClientCertificate, which is
	// rebuilt by Rebuild on every Connect call (so a certificate
	// rotated mid-session, or obtained for the first time after
	// RunSession started retrying, is picked up on the next attempt
	// rather than requiring a brand new RealConnector/RunSession call).
	Config func() controlclient.Config
	// Rand supplies DialBackoff's jitter source; defaults to
	// rand.Float64 if nil (production). Tests inject a deterministic
	// source.
	Rand func() float64
}

// Connect implements Connector.
func (c *RealConnector) Connect(ctx context.Context, hello func() controlclient.HelloFields, touch func()) (ControlStream, func() error, error) {
	randFn := c.Rand
	if randFn == nil {
		randFn = rand.Float64 //nolint:gosec // G404: reconnect jitter, not security-sensitive (mirrors controlclient.Dial's own convention)
	}
	appAttempt := 0
	for {
		stream, closer, err := c.connectOnce(ctx, hello)
		if err == nil {
			return stream, closer, nil
		}
		if ctx.Err() != nil {
			// Connect is done, not merely this attempt's deadline:
			// nothing left to retry.
			return nil, nil, ctx.Err()
		}
		delay := controlclient.DialBackoff(appAttempt, randFn())
		appAttempt++
		if !sleepWithTouch(ctx, delay, touch) {
			return nil, nil, ctx.Err()
		}
	}
}

// connectOnce runs exactly one Dial-through-Hello/HelloAck attempt
// under limits.ControlConnectAttemptTimeout (R6A-4): without a bound
// here, an attempt stuck anywhere in that sequence (a black-holed dial,
// a controller that opens the stream but never answers Hello) would
// never return, yet connectWithDegradedWatch's own touch ticker keeps
// reporting progress regardless, so neither the liveness watchdog nor
// RunSession's reconnect/backoff bookkeeping would ever notice. The
// deadline is attached via context.WithCancel plus a disarmable
// time.AfterFunc rather than context.WithTimeout, so a successful
// attempt's returned stream is NOT later torn down when the deadline
// would otherwise have fired -- attemptCtx stays derived from (and so
// still responds to cancellation of) the caller's ctx for the stream's
// entire remaining lifetime.
func (c *RealConnector) connectOnce(ctx context.Context, hello func() controlclient.HelloFields) (ControlStream, func() error, error) {
	attemptCtx, cancel := context.WithCancel(ctx)
	deadline := time.AfterFunc(limits.ControlConnectAttemptTimeout, cancel)

	conn, err := controlclient.Dial(attemptCtx, c.Config())
	if err != nil {
		deadline.Stop()
		cancel()
		return nil, nil, err
	}
	stream, cerr := controlclient.AgentControlClient(conn).Connect(attemptCtx)
	if cerr == nil {
		var ack *controlv1.HelloAck
		ack, cerr = controlclient.SendHello(stream, 1, hello())
		if cerr == nil {
			_ = ack         // PCR re-attestation (the quote over this nonce) is a later step; step-06a scope stops at HelloAck.
			deadline.Stop() // disarm: the attempt succeeded, so the deadline must never cancel the now-live stream.
			return stream, conn.Close, nil
		}
	}
	deadline.Stop()
	cancel()
	_ = conn.Close()
	return nil, nil, cerr
}

// sleepWithTouch blocks for delay (or until ctx is done, returning
// false), calling touch at sessionLivenessTouchInterval while waiting so
// a long reconnect backoff is never mistaken for a stalled component
// (R6A-1).
func sleepWithTouch(ctx context.Context, delay time.Duration, touch func()) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	ticker := time.NewTicker(sessionLivenessTouchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-ticker.C:
			if touch != nil {
				touch()
			}
		}
	}
}
