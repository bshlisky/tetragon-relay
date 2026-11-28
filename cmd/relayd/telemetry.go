package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"runtime"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/config"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/spiffetls"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/telemetry"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// spoolDir is architecture doc 8.5's spool (already in the unit's
// ReadWritePaths).
const spoolDir = "/var/spool/tetragon-relay"

// telemetryDeps is what startTelemetry needs from run()/runTampered().
type telemetryDeps struct {
	cfg         *config.Config
	auditor     agent.Auditor
	sealer      store.KeySealer
	tetraClient *tetra.Client
	liveness    *agent.LivenessRegistry
	bootID      string
	tampered    bool
	// epochs returns the epochs for each batch header ({} in tampered
	// mode).
	epochs     func() map[string]uint64
	clientCert func() tls.Certificate
	caBundle   []*x509.Certificate
	// handoffChunk is telemetry.Config.HandoffChunk (0: the default; set
	// only by the testca build's e3Tuning).
	handoffChunk int
}

// telemetryAuditor adapts agent.Auditor to telemetry.Auditor.
type telemetryAuditor struct{ a agent.Auditor }

func (t telemetryAuditor) Record(step, detail string, err error) {
	t.a.Record(agent.AuditEvent{Step: step, Detail: detail, Err: err})
}

// tetraEventSource narrows *tetra.Client to telemetry.EventSource:
// telemetry never holds a handle that can change policies (ADR 0039
// section 8).
type tetraEventSource struct{ c *tetra.Client }

func (s tetraEventSource) StreamEvents(ctx context.Context, types []tetragonpb.EventType, exclude []string, deliver func([]byte) bool) error {
	return s.c.StreamEvents(ctx, types, exclude, deliver)
}

// startTelemetry builds the pipeline and runs it until ctx ends. A failure
// here is audited and leaves telemetry off; it never stops enforcement or
// the control session (the heartbeat then reports zero).
func startTelemetry(ctx context.Context, d telemetryDeps) (*telemetry.Pipeline, error) {
	storeKey, err := d.sealer.Unseal()
	if err != nil {
		return nil, fmt.Errorf("unseal store key: %w", err)
	}
	key, err := telemetry.DeriveSpoolKey(storeKey)
	clear(storeKey)
	if err != nil {
		return nil, err
	}
	types := make([]tetragonpb.EventType, 0, len(d.cfg.EventTypes))
	for _, n := range d.cfg.EventTypes {
		t, ok := telemetry.EventTypeNames[n]
		if !ok {
			return nil, fmt.Errorf("unknown event type %q", n)
		}
		types = append(types, t)
	}
	redactor, err := telemetry.NewRedactor(d.cfg.ArgvPatterns)
	if err != nil {
		return nil, err
	}
	aud := telemetryAuditor{d.auditor}
	spool, err := telemetry.OpenSpool(telemetry.SpoolConfig{
		Dir: spoolDir, FS: telemetry.OSFS{}, Key: key, MaxBytes: d.cfg.SpoolMaxBytes,
		HostUUID: d.cfg.HostUUID, BootID: d.bootID, AgentVersion: version, Tampered: d.tampered,
		Epochs: d.epochs, Clock: time.Now, Rand: rand.Reader, Auditor: aud,
	})
	if err != nil {
		return nil, fmt.Errorf("open spool: %w", err)
	}
	dialer := &telemetry.GRPCDialer{
		Endpoints: d.cfg.CollectorEndpoints,
		TLS: func() (*tls.Config, error) {
			return spiffetls.ClientTLSConfig(spiffetls.ClientConfig{
				ServerSPIFFEID: d.cfg.CollectorSPIFFEID, ServerCABundle: d.caBundle,
				ClientCertificate: d.clientCert(), Groups: controlclient.DefaultGroups, Clock: time.Now,
			})
		},
	}
	p, err := telemetry.New(telemetry.Config{
		Source: tetraEventSource{d.tetraClient}, EventTypes: types, Redactor: redactor, Spool: spool,
		Dialer: dialer, BatchMaxEvents: d.cfg.BatchMaxEvents, BatchMaxAge: d.cfg.BatchMaxAge,
		MaxEventRate: d.cfg.MaxEventRate, Clock: time.Now, Auditor: aud, Liveness: d.liveness,
		HandoffChunk: d.handoffChunk,
	})
	if err != nil {
		return nil, err
	}
	go p.Run(ctx)
	d.auditor.Record(agent.AuditEvent{Step: "telemetry_started", Detail: fmt.Sprintf("event types %v, %d collector endpoint(s), spool cap %d bytes, non_security budget %d events/s, GOMAXPROCS %d", d.cfg.EventTypes, len(d.cfg.CollectorEndpoints), d.cfg.SpoolMaxBytes, d.cfg.MaxEventRate, runtime.GOMAXPROCS(0))})
	return p, nil
}

// storeEpochs returns the per-scope epochs for telemetry headers from the
// store (the same values the heartbeat reports). A scope whose epoch
// cannot be read is left out rather than reported as 0.
func storeEpochs(st *store.Store, scopes []string) func() map[string]uint64 {
	return func() map[string]uint64 {
		out := make(map[string]uint64, len(scopes))
		for _, s := range scopes {
			if e, err := st.Current(s); err == nil {
				out[s] = e
			}
		}
		return out
	}
}
