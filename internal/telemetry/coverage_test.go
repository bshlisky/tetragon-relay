package telemetry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	telemetryv1 "github.com/bshlisky/tetragon-relay/api/relay/telemetry/v1"
	"github.com/bshlisky/tetragon-relay/internal/spiffetls"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

func issue(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, uri string, eku x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}
	if isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage, tmpl.ExtKeyUsage = true, true, x509.KeyUsageCertSign, nil
	}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	signer, sk := tmpl, key
	if parent != nil {
		signer, sk = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, sk)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

type ackServer struct {
	telemetryv1.UnimplementedCollectorServer
	got atomic.Int64
}

func (s *ackServer) Export(stream grpc.BidiStreamingServer[telemetryv1.Batch, telemetryv1.Ack]) error {
	for {
		b, err := stream.Recv()
		if err != nil {
			return nil //nolint:nilerr // the client closing the stream ends the test server's handler
		}
		h, err := batch.ParseHeader(b.GetHeader())
		if err != nil {
			return err
		}
		s.got.Add(1)
		if err := stream.Send(&telemetryv1.Ack{ChainId: h.ChainID[:], Seq: h.Seq}); err != nil {
			return err
		}
	}
}

// The real dialer over real mTLS: the collector SPIFFE ID is pinned, so a
// server with another ID is refused; with the right one, batches flow and
// are acked.
func TestGRPCDialer_MTLSPinnedEndToEnd(t *testing.T) {
	const collectorID = "spiffe://td/mgmt/collector"
	ca, caKey := issue(t, nil, nil, true, "", 0)
	client, clientKey := issue(t, ca, caKey, false, "spiffe://td/host/"+testHost, x509.ExtKeyUsageClientAuth)
	start := func(id string) (string, *ackServer, func()) {
		srvCert, srvKey := issue(t, ca, caKey, false, id, x509.ExtKeyUsageServerAuth)
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		creds := credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
			Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert.Raw}, PrivateKey: srvKey}},
		})
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		gs := grpc.NewServer(grpc.Creds(creds))
		as := &ackServer{}
		telemetryv1.RegisterCollectorServer(gs, as)
		go func() { _ = gs.Serve(lis) }()
		return lis.Addr().String(), as, gs.Stop
	}
	tlsFn := func() (*tls.Config, error) {
		return spiffetls.ClientTLSConfig(spiffetls.ClientConfig{
			ServerSPIFFEID: collectorID, ServerCABundle: []*x509.Certificate{ca},
			ClientCertificate: tls.Certificate{Certificate: [][]byte{client.Raw}, PrivateKey: clientKey},
			Groups:            []tls.CurveID{tls.CurveP384}, Clock: time.Now,
		})
	}

	// Wrong server identity: refused at the handshake.
	addr, _, stop := start("spiffe://td/mgmt/controller")
	d := &GRPCDialer{Endpoints: []string{addr}, TLS: tlsFn}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if s, closeFn, err := d.Dial(ctx); err == nil {
		err = s.Send(&telemetryv1.Batch{})
		if err == nil {
			_, err = s.Recv()
		}
		closeFn()
		if err == nil || !strings.Contains(err.Error(), "SPIFFE") {
			t.Fatalf("pinned SPIFFE ID not enforced: %v", err)
		}
	}
	cancel()
	stop()

	// Right identity: a whole pipeline drains through it.
	addr, as, stop := start(collectorID)
	defer stop()
	cfg := spoolCfg(t, t.TempDir(), OSFS{}, "boot-a")
	s := mustOpen(t, cfg)
	red, _ := NewRedactor(nil)
	src := &chanSource{ch: make(chan *tetragonpb.GetEventsResponse, 4)}
	p, err := New(Config{
		Source: src, EventTypes: []tetragonpb.EventType{tetragonpb.EventType_PROCESS_EXEC}, Redactor: red, Spool: s,
		Dialer: &GRPCDialer{Endpoints: []string{addr}, TLS: tlsFn}, BatchMaxEvents: 1, BatchMaxAge: time.Hour,
		Clock: time.Now, Auditor: cfg.Auditor, Liveness: &fakeLiveness{}, BackoffMin: 10 * time.Millisecond, BackoffMax: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(rctx); close(done) }()
	src.ch <- exec("/bin/x", "")
	waitFor(t, "acked over mTLS", func() bool { return s.Stats().Backlog == 0 && as.got.Load() >= 2 })
	rcancel()
	<-done

	if _, _, err := (&GRPCDialer{}).Dial(context.Background()); err == nil {
		t.Fatal("empty dialer accepted")
	}
	if _, _, err := (&GRPCDialer{Endpoints: []string{"x"}, TLS: func() (*tls.Config, error) { return nil, errors.New("no cert") }}).Dial(context.Background()); err == nil {
		t.Fatal("TLS error ignored")
	}
}

type stuckStream struct{ ctx context.Context }

func (s stuckStream) Send(*telemetryv1.Batch) error {
	<-s.ctx.Done()
	return s.ctx.Err()
}

func (s stuckStream) Recv() (*telemetryv1.Ack, error) {
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

type stuckDialer struct {
	dials    atomic.Int64
	hangDial bool
}

func (d *stuckDialer) Dial(ctx context.Context) (Stream, func(), error) {
	d.dials.Add(1)
	if d.hangDial {
		<-ctx.Done()
		return stuckStream{ctx}, func() {}, nil
	}
	return stuckStream{ctx}, func() {}, nil
}

// A collector that stops reading (Send blocks) or never answers a dial is
// cut off by the send and dial bounds; the exporter reconnects and keeps
// touching liveness, so a collector outage never stops the watchdog.
func TestExporter_StalledCollectorIsBounded(t *testing.T) {
	for _, hang := range []bool{false, true} {
		cfg := spoolCfg(t, t.TempDir(), OSFS{}, "boot-a")
		s := mustOpen(t, cfg)
		red, _ := NewRedactor(nil)
		d := &stuckDialer{hangDial: hang}
		live := &fakeLiveness{}
		p, _ := New(Config{
			Source: &chanSource{ch: make(chan *tetragonpb.GetEventsResponse)}, EventTypes: []tetragonpb.EventType{1}, Redactor: red, Spool: s,
			Dialer: d, BatchMaxEvents: 1, BatchMaxAge: time.Hour, Clock: time.Now, Auditor: cfg.Auditor, Liveness: live,
			BackoffMin: 5 * time.Millisecond, BackoffMax: 10 * time.Millisecond, SendTimeout: 30 * time.Millisecond, DialTimeout: 30 * time.Millisecond,
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { p.Run(ctx); close(done) }()
		waitFor(t, "several reconnects", func() bool { return d.dials.Load() >= 3 })
		cancel()
		<-done
		if s.Stats().Backlog != 1 {
			t.Fatalf("hang=%v: backlog = %d, the reset batch must stay spooled", hang, s.Stats().Backlog)
		}
	}
}

func TestNew_Validation(t *testing.T) {
	cfg := spoolCfg(t, t.TempDir(), OSFS{}, "b")
	s := mustOpen(t, cfg)
	red, _ := NewRedactor(nil)
	good := Config{Source: &chanSource{}, EventTypes: []tetragonpb.EventType{1}, Redactor: red, Spool: s, Dialer: &memCollector{},
		BatchMaxEvents: 1, BatchMaxAge: time.Second, Clock: time.Now, Auditor: cfg.Auditor, Liveness: &fakeLiveness{}}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"types":  func(c *Config) { c.EventTypes = nil },
		"events": func(c *Config) { c.BatchMaxEvents = 0 },
		"clock":  func(c *Config) { c.Clock = nil },
	} {
		c := good
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRedactor_MapsAndLists(t *testing.T) {
	red, _ := NewRedactor(nil)
	ev := &tetragonpb.GetEventsResponse{Event: &tetragonpb.GetEventsResponse_ProcessExec{ProcessExec: &tetragonpb.ProcessExec{Process: &tetragonpb.Process{
		Pod: &tetragonpb.Pod{PodLabels: map[string]string{"a": "/home/u/.ssh/k", "b": "fine"}},
	}}}}
	red.Redact(ev)
	labels := ev.GetProcessExec().GetProcess().GetPod().GetPodLabels()
	if labels["a"] != HashPath("/home/u/.ssh/k") || labels["b"] != "fine" {
		t.Fatalf("labels = %v", labels)
	}
	k := &tetragonpb.GetEventsResponse{Event: &tetragonpb.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragonpb.ProcessKprobe{
		Args: []*tetragonpb.KprobeArgument{{Arg: &tetragonpb.KprobeArgument_StringArg{StringArg: "/home/u/.ssh/id"}}},
	}}}
	red.Redact(k)
	if got := k.GetProcessKprobe().GetArgs()[0].GetStringArg(); got != HashPath("/home/u/.ssh/id") {
		t.Fatalf("string arg = %q", got)
	}
}

func TestSpool_NameAndHeadEdgeCases(t *testing.T) {
	for _, n := range []string{"x.batch", "1-2-3.batch", "0000000001-zz000000000000000000000000000000-00000000000000000001.batch", "0000000001-00000000000000000000000000000000-00000000000000000000.batch", "0000000001-00000000000000000000000000000000-00000000000000000001.txt"} {
		if _, _, _, ok := parseFileName(n); ok {
			t.Errorf("%q parsed", n)
		}
	}
	dir := t.TempDir()
	cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
	s := mustOpen(t, cfg)
	for _, bad := range []string{"{}\nzz", "{}\n" + strings.Repeat("0", 96), "nohmac"} {
		_ = os.WriteFile(filepath.Join(dir, headName), []byte(bad), 0o600)
		if _, st, _ := s.readHead(); st != headCorrupt {
			t.Errorf("head %q: state %d", bad, st)
		}
	}
	// A head with a valid HMAC but a non-canonical body.
	js := []byte(`{"gen":1, "host_uuid":"h","boot_id":"b","chain_id":"00","seq":1,"hash":"00"}`)
	_ = os.WriteFile(filepath.Join(dir, headName), append(append(js, '\n'), []byte(hexMAC(s, js))...), 0o600)
	if _, st, _ := s.readHead(); st != headCorrupt {
		t.Error("non-canonical head accepted")
	}
	if _, err := s.unseal("x", []byte("short")); !errors.Is(err, ErrSpoolCorrupt) {
		t.Error("short file accepted")
	}
	// A file that was acked between listing and reading.
	e, _ := s.AppendEvents(batch.ClassSecurity, rec(1), 1, 1)
	_ = os.Remove(filepath.Join(dir, e.name))
	if _, _, err := s.Read(e); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Read of a deleted file: %v", err)
	}
}

func hexMAC(s *Spool, js []byte) string {
	const hexd = "0123456789abcdef"
	m := s.mac([]byte(headName), js)
	out := make([]byte, 0, 2*len(m))
	for _, b := range m {
		out = append(out, hexd[b>>4], hexd[b&15])
	}
	return string(out)
}
