package apply

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// fakeState is one snapshot of the fake server's loaded-policy set,
// recorded on every Add/Delete transition for the no-gap invariant checker
// (step 3 prompt Part E1).
type fakeState struct {
	loaded map[string]bool // loaded name -> true
}

// fakeServer is a scriptable FineGuidanceSensors server, step 3 prompt
// Part E1: "a fake Tetragon gRPC server over a real unix socket in a temp
// dir". It tracks every Add/Delete as a timeline of fakeState snapshots
// (timeline field) so tests can assert the no-gap invariant directly over
// the fake's own recorded ground truth, rather than inferring it from the
// Engine's return value alone.
type fakeServer struct {
	tetragonpb.UnimplementedFineGuidanceSensorsServer

	mu sync.Mutex

	version string
	domain  map[string]string // loaded name -> domain
	yaml    map[string]string // loaded name -> the exact document AddTracingPolicy received

	// failAddAfterN, if > 0, makes the (failAddAfterN+1)th AddTracingPolicy
	// call (1-indexed across the whole fake's lifetime) fail.
	failAddAfterN int
	// failAllAdds, if true, makes every AddTracingPolicy call fail
	// (distinct from failAddAfterN so "fail from the very first call" is
	// expressible without an off-by-one against the zero value).
	failAllAdds   bool
	addCount      int
	failDelete    map[string]bool // loaded name -> fail its DeleteTracingPolicy
	listErr       error
	healthRunning bool

	// confirmAsState, if set, is returned as every policy's state from
	// ListTracingPolicies instead of TP_STATE_ENABLED (used to test
	// confirmLoaded's "not exactly TP_STATE_ENABLED" rejection).
	confirmAsState tetragonpb.TracingPolicyState

	events []*tetragonpb.GetEventsResponse
	// subs receive live events (pushLive) on every open GetEvents stream.
	subs map[chan *tetragonpb.GetEventsResponse]bool
	// sentinels holds relay-sentinel policies apart from domain, so the
	// tests' len(f.domain) and no-gap timeline see bundle policies only.
	sentinels map[string]string // name -> domain

	timeline []fakeState
}

func newFakeServer() *fakeServer {
	return &fakeServer{
		version:        "v1.8.0",
		domain:         map[string]string{},
		yaml:           map[string]string{},
		failDelete:     map[string]bool{},
		subs:           map[chan *tetragonpb.GetEventsResponse]bool{},
		sentinels:      map[string]string{},
		healthRunning:  true,
		confirmAsState: tetragonpb.TracingPolicyState_TP_STATE_ENABLED,
	}
}

func (f *fakeServer) snapshotLocked() {
	loaded := make(map[string]bool, len(f.domain))
	for name := range f.domain {
		loaded[name] = true
	}
	f.timeline = append(f.timeline, fakeState{loaded: loaded})
}

func (f *fakeServer) GetVersion(context.Context, *tetragonpb.GetVersionRequest) (*tetragonpb.GetVersionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &tetragonpb.GetVersionResponse{Version: f.version}, nil
}

func (f *fakeServer) GetHealth(context.Context, *tetragonpb.GetHealthStatusRequest) (*tetragonpb.GetHealthStatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status := tetragonpb.HealthStatusResult_HEALTH_STATUS_RUNNING
	if !f.healthRunning {
		status = tetragonpb.HealthStatusResult_HEALTH_STATUS_ERROR
	}
	return &tetragonpb.GetHealthStatusResponse{HealthStatus: []*tetragonpb.HealthStatus{{Status: status}}}, nil
}

func (f *fakeServer) AddTracingPolicy(_ context.Context, req *tetragonpb.AddTracingPolicyRequest) (*tetragonpb.AddTracingPolicyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	name, err := yamlMetadataName(req.GetYaml())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if strings.HasPrefix(name, SentinelPolicyPrefix) {
		f.sentinels[name] = req.GetDomain()
		return &tetragonpb.AddTracingPolicyResponse{}, nil
	}

	f.addCount++
	if f.failAllAdds || (f.failAddAfterN > 0 && f.addCount > f.failAddAfterN) {
		return nil, status.Error(codes.Internal, fmt.Sprintf("fake: forced add failure on add #%d", f.addCount))
	}

	f.domain[name] = req.GetDomain()
	f.yaml[name] = req.GetYaml()
	f.snapshotLocked()
	return &tetragonpb.AddTracingPolicyResponse{}, nil
}

func (f *fakeServer) DeleteTracingPolicy(_ context.Context, req *tetragonpb.DeleteTracingPolicyRequest) (*tetragonpb.DeleteTracingPolicyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDelete[req.GetName()] {
		return nil, status.Error(codes.Internal, "fake: forced delete failure")
	}
	if _, ok := f.sentinels[req.GetName()]; ok {
		delete(f.sentinels, req.GetName())
		return &tetragonpb.DeleteTracingPolicyResponse{}, nil
	}
	delete(f.domain, req.GetName())
	delete(f.yaml, req.GetName())
	f.snapshotLocked()
	return &tetragonpb.DeleteTracingPolicyResponse{}, nil
}

func (f *fakeServer) EnableTracingPolicy(context.Context, *tetragonpb.EnableTracingPolicyRequest) (*tetragonpb.EnableTracingPolicyResponse, error) {
	return &tetragonpb.EnableTracingPolicyResponse{}, nil
}

func (f *fakeServer) DisableTracingPolicy(context.Context, *tetragonpb.DisableTracingPolicyRequest) (*tetragonpb.DisableTracingPolicyResponse, error) {
	return &tetragonpb.DisableTracingPolicyResponse{}, nil
}

func (f *fakeServer) ListTracingPolicies(_ context.Context, req *tetragonpb.ListTracingPoliciesRequest) (*tetragonpb.ListTracingPoliciesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []*tetragonpb.TracingPolicyStatus
	for name, domain := range f.sentinels {
		if req.GetDomain() != "" && domain != req.GetDomain() {
			continue
		}
		out = append(out, &tetragonpb.TracingPolicyStatus{Name: name, Domain: domain, State: tetragonpb.TracingPolicyState_TP_STATE_ENABLED})
	}
	for name, domain := range f.domain {
		if req.GetDomain() != "" && domain != req.GetDomain() {
			continue
		}
		out = append(out, &tetragonpb.TracingPolicyStatus{
			Name:    name,
			Domain:  domain,
			State:   f.confirmAsState,
			Enabled: true, //nolint:staticcheck // SA1019: deprecated upstream; the fake still reports it since Digest (Part D8) reads it
			Mode:    tetragonpb.TracingPolicyMode_TP_MODE_UNKNOWN,
		})
	}
	return &tetragonpb.ListTracingPoliciesResponse{Policies: out}, nil
}

func (f *fakeServer) GetEvents(_ *tetragonpb.GetEventsRequest, stream grpc.ServerStreamingServer[tetragonpb.GetEventsResponse]) error {
	live := make(chan *tetragonpb.GetEventsResponse, 1024)
	f.mu.Lock()
	events := append([]*tetragonpb.GetEventsResponse(nil), f.events...)
	f.subs[live] = true
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.subs, live)
		f.mu.Unlock()
	}()
	for _, e := range events {
		if err := stream.Send(e); err != nil {
			return err
		}
	}
	for {
		select {
		case e := <-live:
			if err := stream.Send(e); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// pushLive sends ev to every open GetEvents stream.
func (f *fakeServer) pushLive(ev tetra.Event) {
	resp := &tetragonpb.GetEventsResponse{}
	switch {
	case ev.Kprobe != nil:
		resp.Event = &tetragonpb.GetEventsResponse_ProcessKprobe{ProcessKprobe: ev.Kprobe}
	default:
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.subs {
		select {
		case ch <- resp:
		default:
		}
	}
}

// startFakeServer starts f on a real unix socket in a fresh temp dir and
// returns a *tetra.Client wired to it (via tetra.NewUnverified, skipping
// Part B2's socket peer verification: see that function's doc comment)
// plus a cleanup func.
func startFakeServer(t *testing.T, f *fakeServer) (*tetra.Client, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "apply")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "s")

	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	tetragonpb.RegisterFineGuidanceSensorsServer(srv, f)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///"+sockPath,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sockPath)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := tetra.NewUnverified(conn, tetra.Config{Timeout: 3 * time.Second})
	cleanup := func() {
		_ = c.Close()
		srv.Stop()
	}
	return c, cleanup
}
