package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	telemetryv1 "github.com/bshlisky/tetragon-relay/api/relay/telemetry/v1"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
)

// Stream is one Export stream.
type Stream interface {
	Send(*telemetryv1.Batch) error
	Recv() (*telemetryv1.Ack, error)
}

// Dialer opens Export streams to the collector.
type Dialer interface {
	// Dial opens one stream; close releases it. ctx bounds the stream's
	// life: canceling it unblocks Send and Recv.
	Dial(ctx context.Context) (stream Stream, closeFn func(), err error)
}

// ErrProtocol is a collector protocol error (ADR 0039 section 6).
var ErrProtocol = errors.New("telemetry: collector protocol error")

// Default bounds on one Send and one Dial (Config.SendTimeout,
// Config.DialTimeout).
const (
	defaultSendTimeout = 20 * time.Second
	defaultDialTimeout = 10 * time.Second
)

type exporter struct {
	p *Pipeline
}

func newExporter(p *Pipeline) *exporter { return &exporter{p: p} }

// run keeps an Export stream open, reconnecting with backoff, and never
// stops for a collector outage. Its liveness proves its own loop.
func (x *exporter) run(ctx context.Context) {
	backoff := x.p.cfg.BackoffMin
	for ctx.Err() == nil {
		x.p.cfg.Liveness.Touch(LivenessExporter)
		progressed, err := x.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrProtocol) {
			x.p.protocolErrors.Add(1)
			x.p.cfg.Auditor.Record("telemetry_protocol_error", "collector protocol error; closing the stream, deleting nothing, reconnecting", err)
		} else {
			x.p.cfg.Auditor.Record("telemetry_stream_ended", "collector stream ended; reconnecting", err)
		}
		if progressed {
			backoff = x.p.cfg.BackoffMin
		}
		if !x.p.sleep(ctx, backoff, LivenessExporter) {
			return
		}
		backoff = min(2*backoff, x.p.cfg.BackoffMax)
	}
}

type ackState struct {
	sent  map[batch.ChainID]uint64
	acked map[batch.ChainID]uint64
}

// check implements ADR 0039 section 6: an ack must name a chain sent on
// this stream, a seq no higher than the highest sent in it, and no lower
// than the last ack for it.
func (a *ackState) check(ack *telemetryv1.Ack) (batch.ChainID, error) {
	var c batch.ChainID
	if len(ack.GetChainId()) != len(c) {
		return c, fmt.Errorf("%w: ack chain_id is %d bytes", ErrProtocol, len(ack.GetChainId()))
	}
	copy(c[:], ack.GetChainId())
	sent, ok := a.sent[c]
	switch {
	case !ok:
		return c, fmt.Errorf("%w: ack for chain %s, not sent on this stream", ErrProtocol, c)
	case ack.GetSeq() > sent:
		return c, fmt.Errorf("%w: ack for chain %s seq %d, highest sent %d", ErrProtocol, c, ack.GetSeq(), sent)
	case ack.GetSeq() < a.acked[c]:
		return c, fmt.Errorf("%w: ack for chain %s went back from %d to %d", ErrProtocol, c, a.acked[c], ack.GetSeq())
	}
	a.acked[c] = ack.GetSeq()
	return c, nil
}

// session runs one stream: it sends every spooled batch in order, then
// each new one as it is spooled, and applies valid acks. It returns on any
// stream error or protocol error; nothing is deleted except on a valid ack.
func (x *exporter) session(ctx context.Context) (progressed bool, err error) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The stream lives on sctx (gRPC binds a stream to the context it was
	// opened with), so the dial timeout cancels sctx itself if it fires.
	dialTimer := time.AfterFunc(x.p.cfg.DialTimeout, cancel)
	stream, closeFn, err := x.p.cfg.Dialer.Dial(sctx)
	if !dialTimer.Stop() && err == nil {
		closeFn()
		return false, fmt.Errorf("telemetry: dial did not complete within %s", x.p.cfg.DialTimeout)
	}
	if err != nil {
		return false, err
	}
	defer closeFn()

	acks := make(chan *telemetryv1.Ack, 64)
	rerr := make(chan error, 1)
	go func() {
		for {
			a, err := stream.Recv()
			if err != nil {
				rerr <- err
				return
			}
			select {
			case acks <- a:
			case <-sctx.Done():
				return
			}
		}
	}()

	st := &ackState{sent: map[batch.ChainID]uint64{}, acked: map[batch.ChainID]uint64{}}
	apply := func(a *telemetryv1.Ack) error {
		c, err := st.check(a)
		if err != nil {
			return err
		}
		if x.p.cfg.Spool.Ack(c, a.GetSeq()) > 0 {
			progressed = true
		}
		return nil
	}
	var cursor *Entry
	tick := time.NewTicker(touchEvery)
	defer tick.Stop()
	for {
		for {
			e, ok := x.p.cfg.Spool.After(cursor)
			if !ok {
				break
			}
			cur := e
			cursor = &cur
			header, payload, rdErr := x.p.cfg.Spool.Read(e)
			if errors.Is(rdErr, fs.ErrNotExist) || errors.Is(rdErr, ErrSpoolCorrupt) {
				continue
			}
			if rdErr != nil {
				return progressed, rdErr
			}
			if err := sendBounded(sctx, cancel, stream, &telemetryv1.Batch{Header: header, Payload: payload}, x.p.cfg.SendTimeout); err != nil {
				return progressed, err
			}
			if e.Seq > st.sent[e.Chain] {
				st.sent[e.Chain] = e.Seq
			}
			x.p.cfg.Liveness.Touch(LivenessExporter)
			select {
			case a := <-acks:
				if err := apply(a); err != nil {
					return progressed, err
				}
			default:
			}
		}
		select {
		case <-ctx.Done():
			return progressed, nil
		case a := <-acks:
			if err := apply(a); err != nil {
				return progressed, err
			}
		case err := <-rerr:
			return progressed, err
		case <-x.p.cfg.Spool.Notify():
		case <-tick.C:
			x.p.cfg.Liveness.Touch(LivenessExporter)
		}
	}
}

// sendBounded sends b, canceling the stream if Send does not return within
// sendTimeout (a collector that stops reading must not stall this loop).
func sendBounded(ctx context.Context, cancel context.CancelFunc, s Stream, b *telemetryv1.Batch, sendTimeout time.Duration) error {
	var timedOut atomic.Bool
	t := time.AfterFunc(sendTimeout, func() { timedOut.Store(true); cancel() })
	err := s.Send(b)
	t.Stop()
	if timedOut.Load() {
		return fmt.Errorf("telemetry: Send did not complete within %s", sendTimeout)
	}
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// GRPCDialer dials the collector over mTLS (ADR 0039 section 8). TLS
// returns a fresh client config each time (internal/spiffetls pinned to
// the collector SPIFFE ID), so a rotated identity is picked up on the next
// dial. Endpoints are tried in turn.
type GRPCDialer struct {
	Endpoints []string
	TLS       func() (*tls.Config, error)
	next      atomic.Uint64
}

// Dial implements Dialer.
func (d *GRPCDialer) Dial(ctx context.Context) (Stream, func(), error) {
	if len(d.Endpoints) == 0 || d.TLS == nil {
		return nil, nil, fmt.Errorf("telemetry: GRPCDialer needs Endpoints and TLS")
	}
	tlsCfg, err := d.TLS()
	if err != nil {
		return nil, nil, err
	}
	ep := d.Endpoints[d.next.Add(1)%uint64(len(d.Endpoints))]
	conn, err := grpc.NewClient("passthrough:///"+ep,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(limits.MaxTelemetryMessageBytes), grpc.MaxCallSendMsgSize(limits.MaxTelemetryMessageBytes)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("telemetry: dial %s: %w", ep, err)
	}
	stream, err := telemetryv1.NewCollectorClient(conn).Export(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("telemetry: Export on %s: %w", ep, err)
	}
	return stream, func() { _ = stream.CloseSend(); _ = conn.Close() }, nil
}
