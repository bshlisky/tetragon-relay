package tetra

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// Client is a verified connection to a single Tetragon daemon, exposing
// exactly the eight RPCs step 3 prompt Part B1 allowlists. It holds no
// other method on *grpc.ClientConn or tetragonpb.FineGuidanceSensorsClient
// callable from outside this file.
type Client struct {
	conn   *grpc.ClientConn
	stub   tetragonpb.FineGuidanceSensorsClient
	cfg    Config
	closed bool
	peer   *peerTracker
}

// peerTracker records the Tetragon process behind each verified
// connection (SO_PEERCRED pid), so a caller can detect a Tetragon restart
// (docs/prompts/step-06b.md D1): Tetragon's API reports no process start
// time, and relayd cannot read another user's /proc entries under the
// unit's ProtectProc=invisible. grpc re-runs Dial's dialer on every
// reconnect, so a restarted Tetragon shows up as a new pid there.
type peerTracker struct {
	mu    sync.Mutex
	pid   int32
	dials uint64
}

func (p *peerTracker) record(pid int32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pid = pid
	p.dials++
}

// Peer reports the pid of the Tetragon process behind the most recent
// verified connection and how many verified connections have been made.
// Both are 0 before the first connection (and always for a client made
// with NewUnverified).
func (c *Client) Peer() (pid int32, dials uint64) {
	if c.peer == nil {
		return 0, 0
	}
	c.peer.mu.Lock()
	defer c.peer.mu.Unlock()
	return c.peer.pid, c.peer.dials
}

// NewUnverified wraps an already-established *grpc.ClientConn as a Client,
// skipping Part B2's socket peer verification entirely. Dial
// (platform-specific, dial_linux.go) is the only production caller. The
// exported name exists so internal/apply's tests (step 3 prompt Part E1:
// "a fake Tetragon gRPC server over a real unix socket in a temp dir") can
// wire a real *Client to a fake server without needing a uid-0-owned
// socket. Part B2's checks are about which process this package will
// *connect to* in production, not about the RPC-level behavior these
// tests exist to exercise, so skipping them here is intentional, not a
// gap: no production code path other than Dial (which performs the real
// B2 checks itself before ever calling this) reaches NewUnverified.
func NewUnverified(conn *grpc.ClientConn, cfg Config) *Client {
	return &Client{conn: conn, stub: tetragonpb.NewFineGuidanceSensorsClient(conn), cfg: cfg}
}

// Close closes the underlying connection. Safe to call more than once.
func (c *Client) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// classifyErr implements Part B3's typed-error mapping, shared by every
// RPC method below. ctx is the per-call context this package created (with
// its own timeout), so ctx.Err() reliably distinguishes "our timeout
// fired" from any other cause.
func classifyErr(ctx context.Context, rpc string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s", ErrTimeout, rpc)
	}
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%w: %s: %w", ErrProtocol, rpc, err)
	}
	switch st.Code() { //nolint:exhaustive // every other code is an ordinary "Tetragon rejected the request" case, handled by the default
	case codes.DeadlineExceeded:
		return fmt.Errorf("%w: %s", ErrTimeout, rpc)
	case codes.Unavailable, codes.Canceled:
		return fmt.Errorf("%w: %s: %s", ErrUnavailable, rpc, truncateMessage(st.Message()))
	case codes.OK:
		return nil
	default:
		return rejectedError(rpc, st.Message())
	}
}

func (c *Client) callCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.cfg.timeout())
}

// AddTracingPolicy loads yaml (already canonical JSON rendered as YAML by
// the caller — Tetragon's AddTracingPolicy accepts either) under domain.
func (c *Client) AddTracingPolicy(ctx context.Context, yaml, domain string) error {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	_, err := c.stub.AddTracingPolicy(cctx, &tetragonpb.AddTracingPolicyRequest{Yaml: yaml, Domain: domain})
	return classifyErr(cctx, "AddTracingPolicy", err)
}

// DeleteTracingPolicy removes a loaded policy by name/domain. Namespace is
// always empty: this project only ever loads cluster-scoped
// TracingPolicy, never TracingPolicyNamespaced (architecture doc 1.2,
// internal/policydoc B4).
func (c *Client) DeleteTracingPolicy(ctx context.Context, name, domain string) error {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	_, err := c.stub.DeleteTracingPolicy(cctx, &tetragonpb.DeleteTracingPolicyRequest{Name: name, Domain: domain})
	return classifyErr(cctx, "DeleteTracingPolicy", err)
}

// EnableTracingPolicy is part of Part B1's allowlist but is unused by
// internal/apply's core paths: it is deprecated server-side and rejected
// unless Tetragon was started with --enable-deprecated-tracingpolicy-grpc
// (ADR 0016). Exposed so the allowlist requirement is met and so a future
// caller with that flag enabled has a typed method to use.
func (c *Client) EnableTracingPolicy(ctx context.Context, name, domain string) error {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	_, err := c.stub.EnableTracingPolicy(cctx, &tetragonpb.EnableTracingPolicyRequest{Name: name, Domain: domain}) //nolint:staticcheck // SA1019: deprecated upstream (ADR 0016); still part of Part B1's required allowlist
	return classifyErr(cctx, "EnableTracingPolicy", err)
}

// DisableTracingPolicy is EnableTracingPolicy's inverse: see its doc
// comment.
func (c *Client) DisableTracingPolicy(ctx context.Context, name, domain string) error {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	_, err := c.stub.DisableTracingPolicy(cctx, &tetragonpb.DisableTracingPolicyRequest{Name: name, Domain: domain}) //nolint:staticcheck // SA1019: deprecated upstream (ADR 0016); still part of Part B1's required allowlist
	return classifyErr(cctx, "DisableTracingPolicy", err)
}

// TracingPolicyStatus is this package's own copy of the fields
// internal/apply needs from tetragonpb.TracingPolicyStatus, so callers
// never need to import the vendored protobuf package directly.
type TracingPolicyStatus struct {
	ID     uint64
	Name   string
	Domain string
	State  tetragonpb.TracingPolicyState
	// Enabled is TracingPolicyStatus.enabled (sensors.proto:143),
	// deprecated upstream in favor of State but still part of the
	// (loaded name, state, enabled, mode, sensors) digest tuple step 3
	// prompt Part D8 specifies.
	Enabled  bool
	Mode     tetragonpb.TracingPolicyMode
	Sensors  []string
	Error    string
	FilterID uint64
}

// ListTracingPolicies lists every policy in domain ("" lists every domain:
// sensors.proto's own doc comment for ListTracingPoliciesRequest.domain).
func (c *Client) ListTracingPolicies(ctx context.Context, domain string) ([]TracingPolicyStatus, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	resp, err := c.stub.ListTracingPolicies(cctx, &tetragonpb.ListTracingPoliciesRequest{Domain: domain})
	if err != nil {
		return nil, classifyErr(cctx, "ListTracingPolicies", err)
	}
	out := make([]TracingPolicyStatus, 0, len(resp.GetPolicies()))
	for _, p := range resp.GetPolicies() {
		out = append(out, TracingPolicyStatus{
			ID:       p.GetId(),
			Name:     p.GetName(),
			Domain:   p.GetDomain(),
			State:    p.GetState(),
			Enabled:  p.GetEnabled(), //nolint:staticcheck // SA1019: deprecated upstream; still part of Part D8's digest tuple
			Mode:     p.GetMode(),
			Sensors:  append([]string(nil), p.GetSensors()...),
			Error:    p.GetError(),
			FilterID: p.GetFilterId(),
		})
	}
	return out, nil
}

// GetHealth returns Tetragon's health status entries.
func (c *Client) GetHealth(ctx context.Context) ([]*tetragonpb.HealthStatus, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	resp, err := c.stub.GetHealth(cctx, &tetragonpb.GetHealthStatusRequest{})
	if err != nil {
		return nil, classifyErr(cctx, "GetHealth", err)
	}
	return resp.GetHealthStatus(), nil
}

// GetVersion returns Tetragon's raw version string, verified against
// limits.TetragonVersionPattern by RequireVersion (Part B4); GetVersion
// itself never refuses on behalf of the caller, since some callers (e.g. a
// future CLI inspection tool) may legitimately want to see a mismatched
// version rather than get an error.
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	resp, err := c.stub.GetVersion(cctx, &tetragonpb.GetVersionRequest{})
	if err != nil {
		return "", classifyErr(cctx, "GetVersion", err)
	}
	return resp.GetVersion(), nil
}

// RequireVersion implements Part B4's version gate: GetVersion must equal
// the pinned v1.8.x family or this returns ErrUnsupportedVersion. Callers
// (internal/apply) must call this once per Client before issuing any
// mutating RPC.
func (c *Client) RequireVersion(ctx context.Context) (string, error) {
	v, err := c.GetVersion(ctx)
	if err != nil {
		return "", err
	}
	if !limits.TetragonVersionPattern.MatchString(v) {
		return v, fmt.Errorf("%w: got %q, want %s.x", ErrUnsupportedVersion, v, limits.TetragonVersionFamily)
	}
	return v, nil
}

// Event is this package's own copy of the GetEvents fields internal/apply's
// health window (Part D5) needs, so callers never need to import the
// vendored protobuf package directly. Exactly one of Kprobe/Uprobe/Lsm is
// non-nil, mirroring the oneof the underlying GetEventsResponse carries
// (events.proto:199-224); every other event type (exec, exit, ...) is
// skipped before it ever becomes an Event (see events() below), since
// Part D5 only cares about enforcement-shaped events.
type Event struct {
	Kprobe *tetragonpb.ProcessKprobe
	Uprobe *tetragonpb.ProcessUprobe
	Lsm    *tetragonpb.ProcessLsm
}

// GetEvents streams enforcement-relevant events (PROCESS_KPROBE,
// PROCESS_UPROBE, PROCESS_LSM; Part D5 only inspects these three) matching
// policyNames into the returned channel, until ctx is canceled or an error
// occurs (sent as the final receive on errc, then both channels close).
// The request never asks for every event type: Filter.event_set bounds
// what Tetragon sends, keeping Part B3's "bounded response sizes"
// meaningful (an unfiltered stream on a busy host could otherwise dwarf
// MaxGetEventsResponseBytes-per-message with irrelevant volume, not size,
// but there is no reason to ask for more than Part D5 needs either way).
func (c *Client) GetEvents(ctx context.Context, policyNames []string) (<-chan Event, <-chan error) {
	events := make(chan Event)
	errc := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errc)
		stream, err := c.stub.GetEvents(ctx, &tetragonpb.GetEventsRequest{
			AllowList: []*tetragonpb.Filter{{
				EventSet:    []tetragonpb.EventType{tetragonpb.EventType_PROCESS_KPROBE, tetragonpb.EventType_PROCESS_UPROBE, tetragonpb.EventType_PROCESS_LSM},
				PolicyNames: policyNames,
			}},
		})
		if err != nil {
			// step-03a-review.md R3-4: do not report ctx's own
			// cancellation/deadline as a typed error. A caller racing
			// ctx's own expiry against this goroutine (internal/apply's
			// health window does exactly this) would otherwise see a
			// spurious error that fired only because ctx ended, not
			// because anything about Tetragon or the stream failed;
			// closing errc without sending lets such a caller treat
			// "ctx ended" and "GetEvents reported nothing more" as the
			// same, unambiguous signal.
			if ctx.Err() != nil {
				return
			}
			errc <- classifyErr(ctx, "GetEvents", err)
			return
		}
		for {
			resp, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				errc <- classifyErr(ctx, "GetEvents", err)
				return
			}
			var ev Event
			switch e := resp.GetEvent().(type) {
			case *tetragonpb.GetEventsResponse_ProcessKprobe:
				ev.Kprobe = e.ProcessKprobe
			case *tetragonpb.GetEventsResponse_ProcessUprobe:
				ev.Uprobe = e.ProcessUprobe
			case *tetragonpb.GetEventsResponse_ProcessLsm:
				ev.Lsm = e.ProcessLsm
			default:
				continue
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return events, errc
}
