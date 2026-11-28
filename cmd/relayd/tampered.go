package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/config"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/hostprobe"
	"github.com/bshlisky/tetragon-relay/internal/identity"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
	"github.com/bshlisky/tetragon-relay/internal/tpm"
)

// runTampered is relayd's tampered mode (ADR 0038; docs/reviews/
// step-06b-review.md R6B-5). agent.Startup found the store TAMPERED, so
// no epoch, LKG or trust root can be trusted. Instead of exiting (which
// looks the same to the controller as an unplugged host), relayd:
//
//   - builds no apply engine, apply worker or reconcile scheduler, so
//     nothing here can write to Tetragon;
//   - never opens the store again, except to write the REVOKED marker
//     best-effort on Terminate{REVOKED};
//   - loads the existing identity and never creates or rotates one;
//   - connects, sends Alert{TAMPER} after every HelloAck, then
//     heartbeats with live loaded_digest/health and an empty epochs map;
//   - answers every bundle REJECTED_TAMPERED and every trust update with
//     Alert{TRUST_UPDATE_REJECTED}.
//
// The state machine sits in TAMPERED until restart (or REVOKED). The
// session runner is the only liveness component, so the watchdog keeps
// being fed while it is healthy; a collector or controller outage never
// stops it.
func runTampered(cfg *config.Config, auditor *agentAuditor, tpmConn transport.TPM, tpmComponents *agent.TPMComponents, tamperErr error) error {
	auditor.Record(agent.AuditEvent{Step: "tampered_mode", Detail: "store TAMPERED at startup: tampered mode (no Tetragon writes, no store writes, every bundle and trust update rejected) until operator re-enrollment", Err: tamperErr})

	bootID := ""
	hostCaps, factsErr := hostprobe.Load(hostprobe.HostFactsPath)
	if facts, ok := hostCaps.Facts(); ok {
		bootID = facts.BootID
	}
	if factsErr != nil {
		auditor.Record(agent.AuditEvent{Step: "host_facts", Detail: "host facts missing or stale; Hello carries no boot_id", Err: factsErr})
	}

	tetraClient, err := tetra.Dial(context.Background(), tetra.Config{
		SocketPath:           cfg.TetragonSocket,
		RelayGroupName:       relayPersistGroup,
		AllowSELinuxDisabled: cfg.AllowSELinuxDisabled,
	})
	if err != nil {
		return fmt.Errorf("dial tetragon: %w", err)
	}
	defer func() { _ = tetraClient.Close() }()

	liveness, err := agent.NewLivenessRegistry(time.Now)
	if err != nil {
		return fmt.Errorf("new liveness registry: %w", err)
	}
	assembled := &assembledAgent{HostCaps: hostCaps, HostFactsFresh: factsErr == nil, Liveness: liveness}

	// The identity as it is: never generate a host key here.
	hostSigner, err := tpm.LoadHostSigner(tpmConn, storeDir+"/host-signer.json")
	if err != nil {
		auditor.Record(agent.AuditEvent{Step: "identity", Detail: "tampered mode: no usable host signing key; not connecting", Err: err})
		return runUntilSignal(auditor, assembled)
	}
	enrollmentBundle, err := loadCertPoolPEM(cfg.EnrollmentTrustBundle)
	if err != nil {
		return fmt.Errorf("load enrollment trust bundle: %w", err)
	}
	certManager, err := identity.NewCertManager(identity.Config{
		TrustDomain:           cfg.IdentityTrustDomain,
		HostUUID:              cfg.HostUUID,
		EnrollmentTrustBundle: enrollmentBundle,
		MaxCertTTL:            24 * time.Hour,
		ClockSkew:             5 * time.Minute,
		StoreDir:              storeDir,
		RotationInterval:      cfg.KeyRotation,
	}, hostSigner, buildEnroller(cfg))
	if err != nil {
		return fmt.Errorf("new cert manager: %w", err)
	}
	if loadErr := certManager.Load(); loadErr != nil && !errors.Is(loadErr, identity.ErrNoPersistedChain) {
		return fmt.Errorf("load persisted identity: %w", loadErr)
	}
	if len(certManager.Chain()) == 0 {
		auditor.Record(agent.AuditEvent{Step: "identity", Detail: "tampered mode: no persisted identity; not connecting"})
		return runUntilSignal(auditor, assembled)
	}

	sessionCtx, cancelSession := context.WithCancel(context.Background())
	sm, err := agent.NewStateMachine(auditor)
	if err != nil {
		cancelSession()
		return fmt.Errorf("new state machine: %w", err)
	}
	for _, e := range []agent.Event{agent.EventJoinTokenValid, agent.EventSVIDIssued, agent.EventStoreTampered} {
		if err := sm.Fire(e); err != nil {
			cancelSession()
			return fmt.Errorf("enter TAMPERED: %w", err)
		}
	}

	snapshot := &agent.TamperedSnapshotProvider{Client: tetraClient}
	controlLoop, err := agent.NewControlLoop(sm, auditor, time.Now, snapshot, &agent.RealIdentityRotator{CertManager: certManager})
	if err != nil {
		cancelSession()
		return fmt.Errorf("new control loop: %w", err)
	}
	outbox, err := agent.NewOutbox(auditor)
	if err != nil {
		cancelSession()
		return fmt.Errorf("new outbox: %w", err)
	}
	alerter, err := agent.NewAlerter(outbox, auditor, time.Now)
	if err != nil {
		cancelSession()
		return fmt.Errorf("new alerter: %w", err)
	}
	jobs, err := agent.NewTamperedJobs(outbox, alerter, auditor)
	if err != nil {
		cancelSession()
		return fmt.Errorf("new tampered jobs: %w", err)
	}
	controlLoop.Jobs = jobs

	// Telemetry keeps running in tampered mode, on a new chain (reset
	// reason tampered_mode) with empty epochs.
	if pipeline, terr := startTelemetry(sessionCtx, telemetryDeps{
		cfg: cfg, auditor: auditor, sealer: tpmComponents.Sealer, tetraClient: tetraClient, liveness: liveness,
		bootID: bootID, tampered: true, epochs: func() map[string]uint64 { return map[string]uint64{} },
		clientCert: func() tls.Certificate { return clientCertificate(certManager.Chain(), hostSigner) },
		caBundle:   enrollmentBundle,
	}); terr != nil {
		auditor.Record(agent.AuditEvent{Step: "telemetry_disabled", Detail: "telemetry pipeline did not start in tampered mode", Err: terr})
	} else {
		controlLoop.Telemetry = pipeline
	}

	buildDigest, digestErr := agentBuildDigest()
	if digestErr != nil {
		auditor.Record(agent.AuditEvent{Step: "agent_build_digest", Detail: "could not hash /proc/self/exe; Hello will carry no agent_build_digest", Err: digestErr})
	}

	sessionCfg := agent.SessionConfig{
		Connector: &agent.RealConnector{
			Config: func() controlclient.Config {
				return controlclient.Config{
					Endpoints:          cfg.ControllerEndpoints,
					ControllerSPIFFEID: cfg.ControllerSPIFFEID,
					ControllerCABundle: enrollmentBundle,
					ClientCertificate:  clientCertificate(certManager.Chain(), hostSigner),
					Clock:              time.Now,
				}
			},
		},
		Hello: func() controlclient.HelloFields {
			return buildHelloFields(sessionCtx, cfg, nil, tetraClient, bootID, buildDigest, hostCaps.TetragonEnvCollection(), snapshot)
		},
		ControlLoop:       controlLoop,
		Clock:             time.Now,
		Auditor:           auditor,
		Liveness:          liveness,
		Revocations:       &agent.BestEffortRevocations{Mark: markRevokedBestEffort(tpmComponents)},
		HeartbeatInterval: cfg.HeartbeatInterval,
		Outbox:            outbox,
		OnConnected:       agent.TamperedConnected(alerter, tamperErr),
	}

	sessionDone := make(chan error, 1)
	go func() { sessionDone <- agent.RunSession(sessionCtx, sessionCfg) }()
	assembled.CancelSession = cancelSession
	assembled.SessionDone = sessionDone
	return runUntilSignal(auditor, assembled)
}

// markRevokedBestEffort re-opens the store only to write the REVOKED
// marker (R6B-5). If the index itself is what was tampered, store.Open
// fails again and the marker is not written; RunSession audits that and
// parks anyway. Server-side revocation is authoritative.
func markRevokedBestEffort(c *agent.TPMComponents) func(time.Time, string) error {
	return func(at time.Time, reason string) error {
		st, err := store.Open(storeDir, c.Sealer, c.Counter)
		if err != nil {
			return fmt.Errorf("tampered mode: re-open store for the REVOKED marker: %w", err)
		}
		defer func() { _ = st.Close() }()
		return st.MarkRevoked(at, reason)
	}
}
