package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/config"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

// clientCertificate builds the tls.Certificate controlclient.Config
// needs from chain (certManager.Chain(), public data only) and signer
// (the TPM-backed crypto.Signer the chain's leaf key belongs to): the
// private key never leaves the TPM, matching every other place this
// repository builds a tls.Certificate from a TPM-held key (e.g.
// internal/identity's own tests, under the testca build tag).
func clientCertificate(chain []*x509.Certificate, signer crypto.Signer) tls.Certificate {
	der := make([][]byte, len(chain))
	for i, c := range chain {
		der[i] = c.Raw
	}
	var leaf *x509.Certificate
	if len(chain) > 0 {
		leaf = chain[0]
	}
	return tls.Certificate{Certificate: der, PrivateKey: signer, Leaf: leaf}
}

// buildHelloFields assembles controlclient.HelloFields (architecture doc
// 6.2) from this process's already-built components. Every lookup here
// is best-effort: a Hello with some fields empty (e.g. Tetragon
// temporarily unreachable) is still useful to the controller, so a
// failure to read one field must never stop RunSession from sending
// Hello at all -- the reconnect/backoff loop around this function
// (internal/agent.RunSession) is the only thing that should ever decide
// a connection attempt failed.
//
// buildDigest is computed once at startup (agentBuildDigest hashes the
// whole running binary) and passed in rather than recomputed on every
// call: Hello is rebuilt fresh on every reconnect attempt, and the
// binary on disk cannot change out from under an already-running
// process, so re-hashing it every attempt would be pure waste.
func buildHelloFields(ctx context.Context, cfg *config.Config, startupResult *agent.StartupResult, tetraClient *tetra.Client, bootID, buildDigest string, snapshot agent.SnapshotProvider) controlclient.HelloFields {
	fields := controlclient.HelloFields{
		HostUUID:         cfg.HostUUID,
		AgentVersion:     version,
		BootID:           bootID,
		ConfigDigest:     cfg.Digest(),
		AgentBuildDigest: buildDigest,
	}
	if tv, err := tetraClient.GetVersion(ctx); err == nil {
		fields.TetragonVersion = tv
	}
	if raw, rootVersion, ok, err := startupResult.Store.TrustRoot(); err == nil && ok {
		sum := sha256.Sum256(raw)
		fields.TrustRootDigest = sum[:]
		fields.TrustRootVersion = rootVersion
	}
	if snap, err := snapshot.Snapshot(ctx); err == nil {
		fields.Epochs = snap.Epochs
		fields.LoadedDigest = snap.LoadedDigest
		fields.LKGBundleDigest = snap.LKGBundleDigest
	}
	return fields
}

// agentBuildDigest hashes the running binary (/proc/self/exe), per
// control.proto Hello.agent_build_digest's own doc comment. Linux-only
// (the only platform this project targets in production); best-effort,
// like every other buildHelloFields lookup.
func agentBuildDigest() (string, error) {
	data, err := os.ReadFile("/proc/self/exe") //nolint:gosec // G304: fixed, well-known path, not attacker-controlled
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hexEncode(sum[:]), nil
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}
