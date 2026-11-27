// Command relayd is the on-host relay agent described in architecture doc
// section 8. This step (docs/prompts/step-06a.md Part C) wires the
// startup sequence this repository already implements piece by piece
// (internal/agent.Startup, internal/tpm, internal/identity, internal/
// tetra, internal/apply, internal/controlclient) into a running process.
//
// Production builds (no test build tags) never fall back to a test
// enroller or a non-/dev/tpmrm0 TPM transport (Parts C2/C3): a host with
// no real Enroller wired in (architecture doc 5.2/5.3: SPIRE or IdM,
// chosen by the customer, not yet built in this repository) starts,
// keeps enforcing LKG, and stays in UNENROLLED with a clear audit record.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/audit"
	"github.com/bshlisky/tetragon-relay/internal/config"
	"github.com/bshlisky/tetragon-relay/internal/controlclient"
	"github.com/bshlisky/tetragon-relay/internal/hostprobe"
	"github.com/bshlisky/tetragon-relay/internal/identity"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
	"github.com/bshlisky/tetragon-relay/internal/tpm"
)

// version is set at build time via -ldflags "-X main.version=...". It
// defaults to "dev" for local builds.
var version = "dev"

// Fixed filesystem locations architecture doc 8.5's table assigns; not
// configurable via relay.yaml (the config loader itself must already
// trust a fixed, hardcoded path convention before any config value can
// be used at all -- the same reasoning internal/config.relayGroupName's
// own doc comment gives for not being configurable).
const (
	defaultConfigPath = "/etc/tetragon-relay/relay.yaml"
	storeDir          = "/var/lib/tetragon-relay"
	trustRootPath     = "/etc/tetragon-relay/trust/root.json"
	sealedKeyBlobPath = storeDir + "/hmac-key.sealed"
	relayPersistGroup = "tetragon-relay"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", defaultConfigPath, "path to relay.yaml")
	// R6A-3/R6A-5: no --tpm-device flag in any build; relayd opens
	// only productionTPMDevice (tpmdevice.go), so docs/prompts/step-06a.md's
	// "only --config and --version" is enforced by the standard flag
	// package itself rejecting an unknown --tpm-device.
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	// step-06a-e3-prompt.md: every build (production included) now has
	// a real local audit sink (internal/audit, ADR 0033): one JSON line
	// per record on stderr, which systemd's own default (no
	// StandardError= override in packaging/systemd/tetragon-relay.service)
	// already forwards to the journal. C4 forbids this from being a
	// testca-only behavior difference, so it is wired here,
	// unconditionally, before anything else in main can fail.
	jsonAuditor, err := audit.NewJSONAuditor(os.Stderr, time.Now)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relayd: new audit sink: %v\n", err)
		os.Exit(1)
	}
	auditor := &agentAuditor{inner: jsonAuditor}
	if err := run(*configPath, auditor); err != nil {
		fmt.Fprintf(os.Stderr, "relayd: %v\n", err)
		os.Exit(1)
	}
}

// agentAuditor adapts internal/audit.JSONAuditor (Record(audit.Event))
// to agent.Auditor (Record(agent.AuditEvent)) -- the same small,
// package-local adapter pattern engineAuditorAdapter below already uses
// to bridge agent.Auditor to apply.Auditor.
type agentAuditor struct {
	inner *audit.JSONAuditor
}

func (a *agentAuditor) Record(e agent.AuditEvent) {
	a.inner.Record(audit.Event{Step: e.Step, Detail: e.Detail, Err: errString(e.Err)})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// run implements Part C1's startup sequence, in order: config, crypto
// self-test + store + trust root (internal/agent.Startup), host facts,
// TPM components, Tetragon client (peer verification), apply engine,
// certificate manager, control client -- then Part C4's sd_notify/
// watchdog/signal handling until the process is asked to stop.
//
// Each stage's failure is fatal (the process exits, systemd's
// Restart=always + RestartSec=2s, packaging/systemd/tetragon-relay.service,
// restarts it): this step does not build an in-process retry loop around
// Startup's own checks (which would risk becoming "a crash loop that
// skips checks" if written carelessly); systemd's own supervision model
// already re-runs every check from scratch on every restart, which is
// exactly the "never skip checks" property architecture doc 8.3 asks for.
// Reconcile scheduling (retrying a degraded Tetragon/controller connection
// without restarting the whole process) is explicitly step 6b's job.
func run(configPath string, auditor *agentAuditor) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	for _, relaxation := range cfg.SecurityRelaxations() {
		auditor.Record(agent.AuditEvent{Step: "config_security_relaxation", Detail: relaxation})
	}

	tpmConn, err := openTPMDevice()
	if err != nil {
		return fmt.Errorf("open TPM device: %w", err)
	}
	defer func() { _ = tpmConn.Close() }()

	tpmComponents, err := agent.BuildTPMComponents(tpmConn, sealedKeyBlobPath)
	if err != nil {
		return fmt.Errorf("build TPM components: %w", err)
	}

	initialRoot, err := os.ReadFile(trustRootPath) //nolint:gosec // G304: fixed path, architecture doc 8.5
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read initial trust root %s: %w", trustRootPath, err)
	}

	startupResult, err := agent.Startup(agent.Config{
		StoreDir:         storeDir,
		Sealer:           tpmComponents.Sealer,
		Counter:          tpmComponents.Counter,
		InitialRootBytes: initialRoot,
		Auditor:          auditor,
	}, time.Now())
	if err != nil {
		return fmt.Errorf("agent startup: %w", err)
	}
	defer func() { _ = startupResult.Store.Close() }()

	// Part C1: host facts, refusing enforcement bundles if missing or
	// stale (hostprobe.Load fails closed; consuming its Capabilities into
	// guard-rail decisions is 6b's bundle-processing job).
	//
	// ADR 0034 (docs/reviews/step-06a-e3-decisions.md D3): relayd never
	// reads /proc/sys/kernel/random/boot_id (ProcSubset=pid hides it; E3
	// run 45858158620). Freshness is Load's tmpfs/root-owned/0640 rule,
	// and the boot_id for Hello and telemetry is the one relay-probe
	// recorded this boot. If the facts are not fresh there is no
	// trustworthy boot_id, so Hello carries none (an empty string), and
	// the audit record below says why.
	hostCaps, factsErr := hostprobe.Load(hostprobe.HostFactsPath)
	fresh := factsErr == nil
	bootID := ""
	if facts, ok := hostCaps.Facts(); ok {
		bootID = facts.BootID
	}
	if !fresh {
		auditor.Record(agent.AuditEvent{Step: "host_facts", Detail: "host facts missing or stale; enforcement bundles are rejected (REJECTED_CAPABILITY)", Err: factsErr})
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

	// docs/prompts/step-06b.md B4: the health window's "agent can still
	// reach the controller" check is the real control-stream state.
	link, err := agent.NewLink(time.Now, cfg.HeartbeatInterval)
	if err != nil {
		return fmt.Errorf("new link: %w", err)
	}
	// B1: the engine's LKG writes go through CommitOnPut, which commits
	// the LKG together with the epoch and monitor history the apply
	// worker armed, in one store generation.
	commit := &agent.CommitOnPut{Store: startupResult.Store}
	engine := apply.NewEngine(tetraClient, apply.RealPolicyParser{}, commit, link, &engineAuditorAdapter{auditor.inner}, apply.Config{
		PersistDir: cfg.PersistDir,
		HealthWindow: apply.HealthWindowConfig{
			Window:         cfg.HealthWindow,
			SurgeThreshold: cfg.EnforcementSurgeThreshold,
		},
	})

	// Part D1: the state machine starts in UNENROLLED (architecture doc
	// 8.4) on every boot; it is only advanced by a running control loop
	// (internal/agent.ControlLoop), which this step does not start (see
	// below) since it needs a client certificate this build cannot yet
	// obtain. Constructing it here with nothing to drive it would be
	// dead code, so it is not constructed in this step's main() at all;
	// internal/agent/controlloop_test.go and state_test.go exercise it
	// directly.

	// Part C2: identity. A production build's Enroller always refuses
	// to enroll (buildEnroller); CertManager.Load can still pick up a
	// previously persisted chain (e.g. from a future real enrollment
	// flow run out of band), but a host with no persisted chain and no
	// working Enroller simply stays UNENROLLED.
	hostSigner, err := tpm.NewOrLoadHostSigner(tpmConn, storeDir+"/host-signer.json")
	if err != nil {
		return fmt.Errorf("host signer: %w", err)
	}
	enrollmentBundle, err := loadCertPoolPEM(cfg.EnrollmentTrustBundle)
	if err != nil {
		return fmt.Errorf("load enrollment trust bundle: %w", err)
	}
	identityCfg := identity.Config{
		TrustDomain:           cfg.IdentityTrustDomain,
		HostUUID:              cfg.HostUUID,
		EnrollmentTrustBundle: enrollmentBundle,
		MaxCertTTL:            24 * time.Hour,
		ClockSkew:             5 * time.Minute,
		StoreDir:              storeDir,
		RotationInterval:      cfg.KeyRotation,
	}
	certManager, err := identity.NewCertManager(identityCfg, hostSigner, buildEnroller(cfg))
	if err != nil {
		return fmt.Errorf("new cert manager: %w", err)
	}
	if loadErr := certManager.Load(); loadErr != nil && !errors.Is(loadErr, identity.ErrNoPersistedChain) {
		return fmt.Errorf("load persisted identity: %w", loadErr)
	}

	liveness, err := agent.NewLivenessRegistry(time.Now)
	if err != nil {
		return fmt.Errorf("new liveness registry: %w", err)
	}

	assembled := &assembledAgent{
		HostCaps:       hostCaps,
		HostFactsFresh: fresh,
		Liveness:       liveness,
	}

	// Part D3/C2: a production build's Enroller always refuses to
	// enroll (buildEnroller), so len(certManager.Chain()) == 0 here in
	// every production build -- the session runner below is simply
	// never started, and this host stays UNENROLLED exactly as before
	// this step. A host with a persisted identity chain (e.g. from a
	// future real enrollment flow, or the testca build's own Enroller)
	// does reach the "once an identity exists" session runner D3 asks
	// for.
	if len(certManager.Chain()) == 0 {
		auditor.Record(agent.AuditEvent{Step: "identity", Detail: "no persisted identity and no production Enroller available; staying UNENROLLED (architecture doc 5.2/5.3 enrollment is not yet wired into this binary)"})
		return runUntilSignal(auditor, assembled)
	}

	sessionCtx, cancelSession := context.WithCancel(context.Background())
	sm, err := agent.NewStateMachine(auditor)
	if err != nil {
		cancelSession()
		return fmt.Errorf("new state machine: %w", err)
	}
	// An identity already exists: these two transitions are vacuously
	// true bookkeeping (D3's own precondition for RunSession), not a
	// real enrollment flow -- this build has none (C2).
	if err := sm.Fire(agent.EventJoinTokenValid); err != nil {
		cancelSession()
		return fmt.Errorf("enter ENROLLING: %w", err)
	}
	if err := sm.Fire(agent.EventSVIDIssued); err != nil {
		cancelSession()
		return fmt.Errorf("enter CONNECTING: %w", err)
	}
	// ADR 0035 (step-06a-e3-decisions.md D2): a persisted REVOKED marker
	// puts the agent straight into REVOKED; RunSession then parks without
	// dialing, and the LKG applied at startup stays enforced. A store
	// read error is fatal rather than read as "not revoked".
	if _, err := agent.RestoreRevocation(sm, startupResult.Store, auditor); err != nil {
		cancelSession()
		return err
	}

	snapshotProvider := &agent.RealSnapshotProvider{Store: startupResult.Store, Client: tetraClient, Scopes: cfg.AllowedScopes}
	controlLoop, err := agent.NewControlLoop(sm, auditor, time.Now, snapshotProvider, &agent.RealIdentityRotator{CertManager: certManager})
	if err != nil {
		cancelSession()
		return fmt.Errorf("new control loop: %w", err)
	}

	// Best-effort (see buildHelloFields), but never silent: a failure is
	// audited, so E3 can show /proc/self/exe is readable under the unit's
	// ProcSubset=pid/ProtectProc=invisible (step-06a-e3-decisions.md D3).
	buildDigest, digestErr := agentBuildDigest()
	if digestErr != nil {
		auditor.Record(agent.AuditEvent{Step: "agent_build_digest", Detail: "could not hash /proc/self/exe; Hello will carry no agent_build_digest", Err: digestErr})
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
	trustState, err := agent.NewTrustState(startupResult.TrustRoot)
	if err != nil {
		cancelSession()
		return fmt.Errorf("new trust state: %w", err)
	}
	worker, err := agent.NewApplyWorker(agent.ApplyWorkerConfig{
		Deps: agent.BundleDeps{
			Store:          startupResult.Store,
			Roots:          startupResult.Store,
			Commit:         commit,
			Trust:          trustState,
			Engine:         engine,
			Reconciler:     engine,
			Version:        tetraClient,
			HostCaps:       hostCaps,
			EnforceAllowed: fresh && hostCaps.UsrmergeOK(),
			Crypto:         startupResult.Capabilities,
			HostUUID:       cfg.HostUUID,
			AllowedScopes:  cfg.AllowedScopes,
			Digest: func(ctx context.Context) ([]byte, error) {
				snap, err := snapshotProvider.Snapshot(ctx)
				if err != nil {
					return nil, err
				}
				return snap.LoadedDigest, nil
			},
		},
		SM:           sm,
		Link:         link,
		Outbox:       outbox,
		Alerter:      alerter,
		Auditor:      auditor,
		Liveness:     liveness,
		Clock:        time.Now,
		HealthWindow: cfg.HealthWindow,
	})
	if err != nil {
		cancelSession()
		return fmt.Errorf("new apply worker: %w", err)
	}
	controlLoop.Jobs = worker
	trustExpiry := &agent.TrustExpiryMonitor{Trust: trustState, Alerter: alerter, Clock: time.Now}

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
			return buildHelloFields(sessionCtx, cfg, startupResult, tetraClient, bootID, buildDigest, snapshotProvider)
		},
		ControlLoop:       controlLoop,
		Clock:             time.Now,
		Auditor:           auditor,
		Liveness:          liveness,
		Revocations:       startupResult.Store,
		HeartbeatInterval: cfg.HeartbeatInterval,
		Outbox:            outbox,
		Link:              link,
		OnConnected:       trustExpiry.Connected,
		OnHeartbeat:       trustExpiry.Check,
	}

	// The apply worker outlives individual streams (an apply keeps
	// running across a reconnect) and stops with the session.
	go worker.Run(sessionCtx)
	// docs/prompts/step-06b.md D1: reconcile at start, every 60 s, and
	// at once when Tetragon restarts (a new socket-peer pid).
	scheduler := &agent.ReconcileScheduler{
		Worker: worker, Peer: tetraClient.Peer, Probe: engine.TetragonServing,
		Alerter: alerter, Auditor: auditor, Liveness: liveness, Clock: time.Now,
	}
	go scheduler.Run(sessionCtx)

	sessionDone := make(chan error, 1)
	go func() { sessionDone <- agent.RunSession(sessionCtx, sessionCfg) }()
	assembled.CancelSession = cancelSession
	assembled.SessionDone = sessionDone

	return runUntilSignal(auditor, assembled)
}

// assembledAgent holds the components run() builds that outlive its own
// local scope: handed to runUntilSignal, and (HostCaps/HostFactsFresh)
// to a later step's bundle-processing wiring, so host facts are read
// from hostprobe.HostFactsPath exactly once per process lifetime -- never
// re-read from disk by whatever eventually wires them into the
// guardrails' HostCapabilities (architecture doc 7.5's G8 host-capability
// guardrail).
type assembledAgent struct {
	// HostCaps and HostFactsFresh are hostprobe.Load's result for this
	// boot (R6A-2). HostFactsFresh mirrors whether HostCaps reflects a
	// current, successfully-read probe or hostprobe's fail-closed
	// value; 6b's guardrail wiring must still check HostFactsFresh
	// itself before trusting HostCaps, since a HostCaps obtained from a
	// stale/missing probe is the same fail-closed value Load always
	// returns in that case, not a zero value that would be mistaken
	// for "no capabilities configured."
	HostCaps       *hostprobe.Capabilities
	HostFactsFresh bool

	// Liveness is R6A-1's registry: runUntilSignal's watchdog loop
	// withholds WATCHDOG=1 unless every component registered in it
	// (today: only the session runner, if one was started below) has
	// reported within its own allowed interval.
	Liveness *agent.LivenessRegistry

	// CancelSession and SessionDone are non-nil only when a session
	// runner was actually started (an identity exists, D3);
	// runUntilSignal cancels the session's context on SIGTERM/SIGINT
	// and waits (briefly) for it to stop before returning, so shutdown
	// never leaves a reconnect loop running past process exit.
	CancelSession func()
	SessionDone   <-chan error
}

// runUntilSignal implements Part C4's sd_notify/watchdog/clean-shutdown
// contract: READY once startup completes, a watchdog keepalive every half
// of WatchdogSec (packaging/systemd/tetragon-relay.service: 30s, so every
// 15s here) -- withheld, per R6A-1, unless assembled.Liveness reports
// every registered component as healthy -- and a clean return (never
// touching anything Tetragon has loaded) on SIGTERM/SIGINT, which also
// stops the session runner (if one is running) and waits briefly for it
// to exit.
func runUntilSignal(auditor agent.Auditor, assembled *assembledAgent) error {
	notifySocket := os.Getenv("NOTIFY_SOCKET")
	if err := sdNotify(notifySocket, "READY=1"); err != nil {
		auditor.Record(agent.AuditEvent{Step: "sd_notify", Detail: "READY=1 failed", Err: err})
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	watchdogTicker := time.NewTicker(15 * time.Second)
	defer watchdogTicker.Stop()

	for {
		select {
		case <-sigCh:
			auditor.Record(agent.AuditEvent{Step: "shutdown", Detail: "signal received; stopping (Tetragon policies left unchanged)"})
			_ = sdNotify(notifySocket, "STOPPING=1")
			stopSession(auditor, assembled)
			return nil
		case <-watchdogTicker.C:
			// R6A-1: the watchdog proves only that this select loop is
			// still scheduled, not that every long-running component
			// (today: the session runner) is making progress. Withhold
			// the ping -- and name the stale component in an audit
			// record -- unless every registered component reported
			// within its own allowed interval; systemd restarts relayd
			// after WatchdogSec (30s) if the ping stays withheld.
			if healthy, stale, staleFor := assembled.Liveness.Healthy(); healthy {
				if err := sdNotify(notifySocket, "WATCHDOG=1"); err != nil {
					auditor.Record(agent.AuditEvent{Step: "sd_notify", Detail: "WATCHDOG=1 failed", Err: err})
				}
			} else {
				auditor.Record(agent.AuditEvent{Step: "watchdog_withheld", Detail: fmt.Sprintf("component %q has not reported in %s; withholding WATCHDOG=1", stale, staleFor)})
			}
		}
	}
}

// stopSession cancels the session runner's context (if one was started)
// and waits briefly for it to stop, so SIGTERM never leaves a reconnect
// loop running past process exit.
func stopSession(auditor agent.Auditor, assembled *assembledAgent) {
	if assembled.CancelSession == nil {
		return
	}
	assembled.CancelSession()
	select {
	case err := <-assembled.SessionDone:
		if err != nil {
			auditor.Record(agent.AuditEvent{Step: "session_shutdown", Err: err})
		}
	case <-time.After(5 * time.Second):
		auditor.Record(agent.AuditEvent{Step: "session_shutdown", Detail: "session runner did not stop within 5s of cancellation"})
	}
}

// engineAuditorAdapter adapts apply.Auditor (Step/Detail/Err/Domain/
// Policy) to internal/audit.Sink's Event shape, which already carries
// all five fields -- unlike agentAuditor above (agent.AuditEvent has no
// Domain/Policy), this adapter loses nothing.
type engineAuditorAdapter struct {
	inner *audit.JSONAuditor
}

func (a *engineAuditorAdapter) Record(e apply.AuditEvent) {
	a.inner.Record(audit.Event{Step: e.Step, Detail: e.Detail, Err: errString(e.Err), Domain: e.Domain, Policy: e.Policy})
}
