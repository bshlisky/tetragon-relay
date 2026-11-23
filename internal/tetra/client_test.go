package tetra

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

func TestClient_AddDeleteList_Success(t *testing.T) {
	f := newFakeServer()
	f.policies = []*tetragonpb.TracingPolicyStatus{
		{Name: "a", Domain: "relay-managed", State: tetragonpb.TracingPolicyState_TP_STATE_ENABLED},
	}
	c, cleanup := startFakeServer(t, f)
	defer cleanup()

	ctx := context.Background()
	if err := c.AddTracingPolicy(ctx, "apiVersion: x", "relay-managed"); err != nil {
		t.Fatalf("AddTracingPolicy: %v", err)
	}
	if err := c.DeleteTracingPolicy(ctx, "a", "relay-managed"); err != nil {
		t.Fatalf("DeleteTracingPolicy: %v", err)
	}
	list, err := c.ListTracingPolicies(ctx, "relay-managed")
	if err != nil {
		t.Fatalf("ListTracingPolicies: %v", err)
	}
	if len(list) != 1 || list[0].Name != "a" {
		t.Fatalf("ListTracingPolicies = %+v", list)
	}
}

func TestClient_ErrorClassification(t *testing.T) {
	cases := []struct {
		name    string
		code    codes.Code
		msg     string
		wantErr error
	}{
		{"unavailable", codes.Unavailable, "connection refused", ErrUnavailable},
		{"invalid_argument", codes.InvalidArgument, "bad yaml", ErrRejectedByTetragon},
		{"already_exists", codes.AlreadyExists, "policy exists", ErrRejectedByTetragon},
		{"permission_denied", codes.PermissionDenied, "nope", ErrRejectedByTetragon},
		{"internal", codes.Internal, "boom", ErrRejectedByTetragon},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer()
			f.addErr = status.Error(tc.code, tc.msg)
			c, cleanup := startFakeServer(t, f)
			defer cleanup()

			err := c.AddTracingPolicy(context.Background(), "y", "d")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("AddTracingPolicy error = %v, want wrapping %v", err, tc.wantErr)
			}
		})
	}
}

func TestClient_RejectedMessageTruncated(t *testing.T) {
	f := newFakeServer()
	long := strings.Repeat("x", 2000)
	f.addErr = status.Error(codes.InvalidArgument, long)
	c, cleanup := startFakeServer(t, f)
	defer cleanup()

	err := c.AddTracingPolicy(context.Background(), "y", "d")
	if !errors.Is(err, ErrRejectedByTetragon) {
		t.Fatalf("error = %v, want ErrRejectedByTetragon", err)
	}
	if len(err.Error()) > limits.MaxTetragonErrorMessageBytes+200 {
		t.Fatalf("error message not truncated: %d bytes", len(err.Error()))
	}
}

func TestClient_Timeout(t *testing.T) {
	f := newFakeServer()
	f.healthErr = nil
	c, cleanup := startFakeServer(t, f)
	defer cleanup()
	c.cfg.Timeout = 1 * time.Nanosecond

	_, err := c.GetHealth(context.Background())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("GetHealth error = %v, want ErrTimeout", err)
	}
}

func TestClient_CallerContextCanceled(t *testing.T) {
	f := newFakeServer()
	c, cleanup := startFakeServer(t, f)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.GetVersion(ctx)
	if err == nil {
		t.Fatal("GetVersion with a pre-canceled context returned nil error")
	}
}

func TestClient_RequireVersion(t *testing.T) {
	cases := []struct {
		version string
		wantErr error
	}{
		{"v1.8.0", nil},
		{"v1.8.0-rc1", nil},
		{"v1.8.17", nil},
		{"v1.7.9", ErrUnsupportedVersion},
		{"v2.0.0", ErrUnsupportedVersion},
		{"v1.8", ErrUnsupportedVersion},
		{"garbage", ErrUnsupportedVersion},
		{"", ErrUnsupportedVersion},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			f := newFakeServer()
			f.version = tc.version
			c, cleanup := startFakeServer(t, f)
			defer cleanup()

			v, err := c.RequireVersion(context.Background())
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("RequireVersion(%q): %v", tc.version, err)
				}
				if v != tc.version {
					t.Fatalf("RequireVersion returned %q, want %q", v, tc.version)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RequireVersion(%q) error = %v, want %v", tc.version, err, tc.wantErr)
			}
		})
	}
}

func TestClient_GetEvents_FiltersToEnforcementTypes(t *testing.T) {
	f := newFakeServer()
	f.events = []*tetragonpb.GetEventsResponse{
		{Event: &tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{}}},
		{Event: &tetragonpb.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragonpb.ProcessKprobe{PolicyName: "p1", Action: tetragonpb.KprobeAction_KPROBE_ACTION_SIGKILL}}},
		{Event: &tetragonpb.GetEventsResponse_ProcessUprobe{ProcessUprobe: &tetragonpb.ProcessUprobe{}}},
		{Event: &tetragonpb.GetEventsResponse_ProcessLsm{ProcessLsm: &tetragonpb.ProcessLsm{}}},
	}
	c, cleanup := startFakeServer(t, f)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	events, errc := c.GetEvents(ctx, []string{"p1"})

	var got []Event
	for ev := range events {
		got = append(got, ev)
		if len(got) == 3 {
			cancel()
		}
	}
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unexpected GetEvents error: %v", err)
		}
	default:
	}
	if len(got) != 3 {
		t.Fatalf("got %d events, want exactly the 3 enforcement-shaped ones (process_exec must be skipped): %+v", len(got), got)
	}
	if got[0].Kprobe == nil || got[0].Kprobe.PolicyName != "p1" {
		t.Fatalf("first event = %+v, want the ProcessKprobe", got[0])
	}
}

func TestClassifyErr(t *testing.T) {
	ctx := context.Background()
	if err := classifyErr(ctx, "X", nil); err != nil {
		t.Fatalf("nil error should classify to nil, got %v", err)
	}
	plain := errors.New("plain, non-grpc error")
	if err := classifyErr(ctx, "X", plain); !errors.Is(err, ErrProtocol) {
		t.Fatalf("non-status error classified as %v, want ErrProtocol", err)
	}
	if err := classifyErr(ctx, "X", status.Error(codes.OK, "")); err != nil {
		t.Fatalf("codes.OK should classify to nil, got %v", err)
	}
}

func TestClient_GetHealth_Error(t *testing.T) {
	f := newFakeServer()
	f.healthErr = status.Error(codes.Internal, "down")
	c, cleanup := startFakeServer(t, f)
	defer cleanup()
	if _, err := c.GetHealth(context.Background()); !errors.Is(err, ErrRejectedByTetragon) {
		t.Fatalf("GetHealth error = %v, want ErrRejectedByTetragon", err)
	}
}

func TestClient_ListTracingPolicies_Error(t *testing.T) {
	f := newFakeServer()
	f.listErr = status.Error(codes.Unavailable, "down")
	c, cleanup := startFakeServer(t, f)
	defer cleanup()
	if _, err := c.ListTracingPolicies(context.Background(), ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ListTracingPolicies error = %v, want ErrUnavailable", err)
	}
}

func TestClient_GetEvents_StreamStartError(t *testing.T) {
	f := newFakeServer()
	c, cleanup := startFakeServer(t, f)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events, errc := c.GetEvents(ctx, nil)
	for range events {
	}
	if err := <-errc; err == nil {
		t.Fatal("GetEvents with a pre-canceled context produced no error")
	}
}

func TestClient_EnableDisableTracingPolicy(t *testing.T) {
	c, cleanup := startFakeServer(t, newFakeServer())
	defer cleanup()
	ctx := context.Background()
	if err := c.EnableTracingPolicy(ctx, "a", "d"); err != nil {
		t.Fatalf("EnableTracingPolicy: %v", err)
	}
	if err := c.DisableTracingPolicy(ctx, "a", "d"); err != nil {
		t.Fatalf("DisableTracingPolicy: %v", err)
	}
}

func TestClient_CloseIsIdempotent(t *testing.T) {
	c, cleanup := startFakeServer(t, newFakeServer())
	defer cleanup()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
