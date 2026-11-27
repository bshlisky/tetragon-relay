//go:build e3

// Command e3collector is step 7a's E3 test collector: a
// relay.telemetry.v1.Collector over mTLS that runs the reference chain
// verifier (internal/telemetry/chainverify) and prints every batch header
// and verdict.
//
//	e3collector serve  --listen ADDR --ca-cert CA --cert C --key K --store FILE [--hostile-ack-once]
//	e3collector report --store FILE --host-uuid H [--decode]
//
// serve appends every batch it receives to FILE (fsynced) before acking
// it, so the verdict survives a collector restart (T-S2). report re-runs
// the verifier over FILE, prints every header and finding, and exits 1 if
// the chain is not clean. --decode also prints each event's redacted
// fields (T-S1).
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	telemetryv1 "github.com/bshlisky/tetragon-relay/api/relay/telemetry/v1"
	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/chainverify"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: e3collector serve|report ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "report":
		err = report(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "e3collector: FAIL: %v\n", err)
		os.Exit(1)
	}
}

type record struct {
	H string `json:"h"`
	P string `json:"p"`
}

type store struct {
	mu sync.Mutex
	f  *os.File
}

func (s *store) append(h, p []byte) error {
	b, _ := json.Marshal(record{H: base64.StdEncoding.EncodeToString(h), P: base64.StdEncoding.EncodeToString(p)})
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return s.f.Sync()
}

func load(path string) ([]chainverify.Input, error) {
	f, err := os.Open(path) //nolint:gosec // G304: operator-supplied flag for this CI tool
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []chainverify.Input
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 4*limits.MaxTelemetryMessageBytes)
	for sc.Scan() {
		var r record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		h, err1 := base64.StdEncoding.DecodeString(r.H)
		p, err2 := base64.StdEncoding.DecodeString(r.P)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("bad record")
		}
		out = append(out, chainverify.Input{Header: h, Payload: p})
	}
	return out, sc.Err()
}

type server struct {
	telemetryv1.UnimplementedCollectorServer
	st          *store
	mu          sync.Mutex
	v           *chainverify.Verifier
	hostileOnce bool
	hostileDone atomic.Bool
	streams     atomic.Int64
	trustDomain string
}

func hostFromPeer(ctx context.Context, td string) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 || len(ti.State.PeerCertificates[0].URIs) != 1 {
		return "", errors.New("no client certificate URI")
	}
	u := ti.State.PeerCertificates[0].URIs[0].String()
	prefix := "spiffe://" + td + "/host/"
	if !strings.HasPrefix(u, prefix) {
		return "", fmt.Errorf("client SPIFFE ID %q is not a host of %s", u, td)
	}
	return strings.TrimPrefix(u, prefix), nil
}

func (s *server) Export(stream grpc.BidiStreamingServer[telemetryv1.Batch, telemetryv1.Ack]) error {
	n := s.streams.Add(1)
	host, err := hostFromPeer(stream.Context(), s.trustDomain)
	if err != nil {
		return err
	}
	fmt.Printf("e3collector: [%s] stream #%d from host %s\n", stamp(), n, host)
	for {
		b, err := stream.Recv()
		if err != nil {
			fmt.Printf("e3collector: [%s] stream #%d ended: %v\n", stamp(), n, err)
			return nil //nolint:nilerr // stream end is normal
		}
		h, herr := batch.ParseHeader(b.GetHeader())
		if herr == nil && h.HostUUID != host {
			return fmt.Errorf("header host_uuid %q does not match the client certificate's %q", h.HostUUID, host)
		}
		if err := s.st.append(b.GetHeader(), b.GetPayload()); err != nil {
			return err
		}
		s.mu.Lock()
		findings := s.v.Add(b.GetHeader(), b.GetPayload())
		s.mu.Unlock()
		fmt.Printf("e3collector: [%s] stream #%d batch %s verdict=%s\n", stamp(), n, b.GetHeader(), verdict(findings))
		if herr != nil {
			continue
		}
		ack := &telemetryv1.Ack{ChainId: h.ChainID[:], Seq: h.Seq}
		if s.hostileOnce && s.hostileDone.CompareAndSwap(false, true) {
			ack.Seq = h.Seq + 1000
			fmt.Printf("e3collector: [%s] HOSTILE ack chain=%s seq=%d (only seq %d was sent)\n", stamp(), h.ChainID, ack.Seq, h.Seq)
		}
		if err := stream.Send(ack); err != nil {
			return err
		}
	}
}

func stamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func verdict(fs []chainverify.Finding) string {
	if len(fs) == 0 {
		return "ok"
	}
	var parts []string
	for _, f := range fs {
		parts = append(parts, fmt.Sprintf("%s(%s)", f.Kind, f.Detail))
	}
	return strings.Join(parts, ";")
}

func readPEM(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied flag for this CI tool
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:18444", "address")
	caPath := fs.String("ca-cert", "", "CA the agents' client certificates chain to")
	certPath := fs.String("cert", "", "collector server certificate")
	keyPath := fs.String("key", "", "collector server key")
	td := fs.String("trust-domain", "", "SPIFFE trust domain")
	storePath := fs.String("store", "", "append-only batch store")
	hostile := fs.Bool("hostile-ack-once", false, "T-S5: send one ack for a seq never sent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ca, err := readPEM(*caPath)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		return err
	}
	prior, err := load(*storePath)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*storePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: operator-supplied flag
	if err != nil {
		return err
	}
	s := &server{st: &store{f: f}, v: chainverify.New(""), hostileOnce: *hostile, trustDomain: *td}
	for _, in := range prior {
		s.v.Add(in.Header, in.Payload)
	}
	fmt.Printf("e3collector: [%s] listening on %s (%d batches already stored)\n", stamp(), *listen, len(prior))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	creds := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true,
	})
	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	gs := grpc.NewServer(grpc.Creds(creds), grpc.MaxRecvMsgSize(limits.MaxTelemetryMessageBytes))
	telemetryv1.RegisterCollectorServer(gs, s)
	return gs.Serve(lis)
}

func report(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	storePath := fs.String("store", "", "batch store written by serve")
	host := fs.String("host-uuid", "", "expected host UUID")
	decode := fs.Bool("decode", false, "print each event's redacted fields")
	if err := fs.Parse(args); err != nil {
		return err
	}
	in, err := load(*storePath)
	if err != nil {
		return err
	}
	v := chainverify.New(*host)
	for i, b := range in {
		f := v.Add(b.Header, b.Payload)
		fmt.Printf("REPORT batch %d header=%s verdict=%s\n", i, b.Header, verdict(f))
		if *decode {
			printEvents(b)
		}
	}
	gaps := v.Gaps()
	for _, g := range gaps {
		fmt.Printf("REPORT %s chain=%s seqs=%d..%d\n", g.Kind, g.ChainID, g.Seq, g.LastSeq)
	}
	for _, c := range v.Chains() {
		fmt.Printf("REPORT chain %s boot=%q contiguous=%d max=%d received=%d declared_dropped=%d rate_limited_events=%d reset=%s\n", c.ChainID, c.BootID, c.Contiguous, c.MaxSeq, c.Received, c.Declared, c.RateLimited, c.ResetReason)
	}
	r := chainverify.Verify(*host, in)
	if !r.Clean() {
		return fmt.Errorf("chain not clean: %d finding(s)", len(r.Findings))
	}
	fmt.Printf("REPORT CLEAN: %d batches, %d chain(s), no gap, fork or bad batch\n", len(in), len(r.Chains))
	return nil
}

func printEvents(in chainverify.Input) {
	b, err := batch.Parse(in.Header, in.Payload)
	if err != nil || b.Header.Kind != batch.KindEvents {
		if err == nil && b.Header.Kind != batch.KindEvents {
			fmt.Printf("REPORT   %s payload=%s\n", b.Header.Kind, b.Payload)
		}
		return
	}
	dec, err := batch.NewPayloadDecoder()
	if err != nil {
		return
	}
	defer dec.Close()
	raw, err := dec.Decode(&b.Header, b.Payload)
	if err != nil {
		fmt.Printf("REPORT   events payload does not decode: %v\n", err)
		return
	}
	fmt.Printf("REPORT   events enc=%s count=%d sent=%d decoded=%d\n", b.Header.Encoding(), b.Header.Count, len(b.Payload), len(raw))
	recs, err := batch.SplitRecords(raw, b.Header.Count)
	if err != nil {
		return
	}
	for _, raw := range recs {
		var ev tetragonpb.GetEventsResponse
		if proto.Unmarshal(raw, &ev) != nil {
			continue
		}
		var p *tetragonpb.Process
		var paths []string
		switch e := ev.GetEvent().(type) {
		case *tetragonpb.GetEventsResponse_ProcessExec:
			p = e.ProcessExec.GetProcess()
		case *tetragonpb.GetEventsResponse_ProcessExit:
			p = e.ProcessExit.GetProcess()
		case *tetragonpb.GetEventsResponse_ProcessKprobe:
			p = e.ProcessKprobe.GetProcess()
			for _, a := range e.ProcessKprobe.GetArgs() {
				if f := a.GetFileArg(); f != nil {
					paths = append(paths, f.GetPath())
				}
				if f := a.GetPathArg(); f != nil {
					paths = append(paths, f.GetPath())
				}
				if s := a.GetStringArg(); s != "" {
					paths = append(paths, s)
				}
			}
		}
		fmt.Printf("REPORT   event %T binary=%q arguments=%q env=%d cwd=%q args=%q\n", ev.GetEvent(), p.GetBinary(), p.GetArguments(), len(p.GetEnvironmentVariables()), p.GetCwd(), paths)
	}
}
