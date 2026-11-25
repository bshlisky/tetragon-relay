//go:build testserver

// Command testcontroller is docs/prompts/step-05b.md Part E2's reference
// implementation of the controller's stream gateway handshake ONLY: TLS,
// the client-certificate checks architecture doc 6.3 steps 1-2 describe,
// and Hello/HelloAck. It is NOT a production controller: it never
// forwards policy bundles, tracks heartbeats past the first Hello, or
// persists anything. It exists so the backend team (docs/server-
// contract.md) and this repository's own integration tests have a real,
// runnable reference for the handshake half of the protocol.
//
// Built only with -tags testserver (never part of a default `go build
// ./...`, matching cmd/bundlesign-test's "testtools" tag precedent).
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/testcontroller"
	"google.golang.org/grpc"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("testcontroller", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listenAddr := fs.String("listen", "127.0.0.1:0", "address to listen on")
	trustDomain := fs.String("trust-domain", "mgmt.example.internal", "SPIFFE trust domain agent URI SANs are checked against")
	serverCertFile := fs.String("server-cert", "", "PEM file: server certificate chain (required)")
	serverKeyFile := fs.String("server-key", "", "PEM file: server private key (required)")
	clientCAFile := fs.String("client-ca", "", "PEM file: CA bundle used to verify agent certificates (required)")
	heartbeatSeconds := fs.Uint("heartbeat-seconds", 15, "HeartbeatIntervalSeconds reported in HelloAck")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *serverCertFile == "" || *serverKeyFile == "" || *clientCAFile == "" {
		_, _ = fmt.Fprintln(stderr, "testcontroller: --server-cert, --server-key and --client-ca are all required")
		return 2
	}

	cert, err := tls.LoadX509KeyPair(*serverCertFile, *serverKeyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "testcontroller: load server cert/key: %v\n", err)
		return 1
	}
	caBundle, err := loadCertBundle(*clientCAFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "testcontroller: load client CA bundle: %v\n", err)
		return 1
	}

	srv := testcontroller.NewServer(testcontroller.Config{
		TrustDomain:              *trustDomain,
		ServerCertificate:        cert,
		ClientCABundle:           caBundle,
		HeartbeatIntervalSeconds: uint32(*heartbeatSeconds),
	})
	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "testcontroller: listen on %s: %v\n", *listenAddr, err)
		return 1
	}
	grpcServer := grpc.NewServer(grpc.Creds(srv.Credentials()))
	controlv1.RegisterAgentControlServer(grpcServer, srv)
	_, _ = fmt.Fprintf(stdout, "testcontroller: listening on %s (NOT a production controller)\n", lis.Addr())
	if err := grpcServer.Serve(lis); err != nil {
		_, _ = fmt.Fprintf(stderr, "testcontroller: serve: %v\n", err)
		return 1
	}
	return 0
}

func loadCertBundle(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is an explicit, operator-supplied flag for this test-only tool
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("testcontroller: %s contains no certificates", path)
	}
	return certs, nil
}
