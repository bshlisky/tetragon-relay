package tetra

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// fakeServer is a scriptable, in-memory FineGuidanceSensors server used by
// every test in this package (step 3 prompt Part E1: "a fake Tetragon gRPC
// server over a real unix socket in a temp dir"). It is also reused,
// unmodified, by internal/apply's own tests (step 3 prompt Part D) via the
// same construction pattern, each giving it their own scenario.
type fakeServer struct {
	tetragonpb.UnimplementedFineGuidanceSensorsServer

	mu sync.Mutex

	version string

	// addErr/deleteErr/listErr, when non-nil, are returned by the
	// corresponding RPC every time it is called.
	addErr    error
	deleteErr error
	listErr   error
	healthErr error

	// addHook, if set, is called for every AddTracingPolicy request
	// before addErr is applied, so tests can fail on the Nth add, record
	// a timeline (invariant checker, Part E1), or otherwise react.
	addHook    func(req *tetragonpb.AddTracingPolicyRequest) error
	deleteHook func(req *tetragonpb.DeleteTracingPolicyRequest) error

	policies []*tetragonpb.TracingPolicyStatus

	healthStatus []*tetragonpb.HealthStatus

	events     []*tetragonpb.GetEventsResponse
	eventDelay time.Duration
}

func newFakeServer() *fakeServer {
	return &fakeServer{version: "v1.8.0"}
}

func (f *fakeServer) GetVersion(context.Context, *tetragonpb.GetVersionRequest) (*tetragonpb.GetVersionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &tetragonpb.GetVersionResponse{Version: f.version}, nil
}

func (f *fakeServer) GetHealth(context.Context, *tetragonpb.GetHealthStatusRequest) (*tetragonpb.GetHealthStatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.healthErr != nil {
		return nil, f.healthErr
	}
	return &tetragonpb.GetHealthStatusResponse{HealthStatus: f.healthStatus}, nil
}

func (f *fakeServer) AddTracingPolicy(_ context.Context, req *tetragonpb.AddTracingPolicyRequest) (*tetragonpb.AddTracingPolicyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addHook != nil {
		if err := f.addHook(req); err != nil {
			return nil, err
		}
	}
	if f.addErr != nil {
		return nil, f.addErr
	}
	return &tetragonpb.AddTracingPolicyResponse{}, nil
}

func (f *fakeServer) DeleteTracingPolicy(_ context.Context, req *tetragonpb.DeleteTracingPolicyRequest) (*tetragonpb.DeleteTracingPolicyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteHook != nil {
		if err := f.deleteHook(req); err != nil {
			return nil, err
		}
	}
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
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
	for _, p := range f.policies {
		if req.GetDomain() != "" && p.GetDomain() != req.GetDomain() {
			continue
		}
		out = append(out, p)
	}
	return &tetragonpb.ListTracingPoliciesResponse{Policies: out}, nil
}

func (f *fakeServer) GetEvents(_ *tetragonpb.GetEventsRequest, stream grpc.ServerStreamingServer[tetragonpb.GetEventsResponse]) error {
	f.mu.Lock()
	events := append([]*tetragonpb.GetEventsResponse(nil), f.events...)
	delay := f.eventDelay
	f.mu.Unlock()
	for _, e := range events {
		if delay > 0 {
			time.Sleep(delay)
		}
		if err := stream.Send(e); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// startFakeServer starts f listening on a unix socket inside a fresh temp
// dir and returns a Client wired directly to it via NewUnverified (not Dial:
// see NewUnverified's doc comment for why that is the correct choice for these
// tests) and a cleanup func.
func startFakeServer(t *testing.T, f *fakeServer) (*Client, func()) {
	t.Helper()
	// A short, test-name-independent temp dir: unix socket paths are
	// bounded (~104 bytes on most platforms, including macOS), and
	// t.TempDir() embeds the full (possibly long, subtest-suffixed) test
	// name, which routinely overflows that limit.
	dir, err := os.MkdirTemp("", "tetra")
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
	go srv.Serve(lis) //nolint:errcheck // Stop() below always produces a "use of closed network connection" from Serve's goroutine

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
	c := NewUnverified(conn, Config{Timeout: 2 * time.Second})
	cleanup := func() {
		_ = c.Close()
		srv.Stop()
		_ = os.Remove(sockPath)
	}
	return c, cleanup
}
