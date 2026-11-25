// Package controlclient implements docs/prompts/step-05b.md Part C: the
// mTLS client half of the control channel (architecture doc section 6),
// transport only. It builds the TLS 1.3 configuration (tlsconfig.go),
// dials one of the controller's pinned endpoints with full-jitter
// reconnect backoff (client.go), and performs the Hello/HelloAck exchange
// over the resulting gRPC bidirectional stream (hello.go).
//
// This package has no dependency on internal/identity, internal/tpm,
// internal/store, internal/apply, internal/tetra or internal/hostprobe:
// it takes an already-built tls.Certificate (Config.ClientCertificate)
// and an already-computed HelloFields, so it can be built and tested
// without any of those. Wiring those together is relayd's main() job
// (step 6; see docs/reports/step-05b.md section 11 for exactly where each
// Hello field comes from today).
//
// The full control message loop (heartbeats, bundle handling, trust
// updates, termination handling) is step 6; this package implements only
// connection establishment and the initial Hello/HelloAck handshake.
package controlclient
