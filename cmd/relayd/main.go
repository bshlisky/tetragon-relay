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
	// R6A-3: tpmDeviceFlag only defines a --tpm-device flag under the
	// testtpm build tag (tpmdevice_testtpm.go); a production build
	// (tpmdevice.go) returns a fixed pointer to productionTPMDevice and
	// defines no flag at all, so docs/prompts/step-06a.md's "only
	// --config and --version" is enforced by the standard flag package
	// itself rejecting an unknown --tpm-device in that build.
	tpmDevice := tpmDeviceFlag()
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	auditor := &agent.FakeAuditor{} // step 6a: no off-host audit sink yet (architecture doc section 10 is step 7)
	if err := run(*configPath, *tpmDevice, auditor); err != nil {
		fmt.Fprintf(os.Stderr, "relayd: %v\n", err)
		os.Exit(1)
	}
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
func run(configPath, tpmDevicePath string, auditor agent.Auditor) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	for _, relaxation := range cfg.SecurityRelaxations() {
		auditor.Record(agent.AuditEvent{Step: "config_security_relaxation", Detail: relaxation})
	}

	tpmConn, err := openTPMDevice(tpmDevicePath)
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
	// stale (hostprobe.Load already fails closed on exactly that;
	// consuming its Capabilities into guard-rail decisions is 6b's
	// bundle-processing job).
	//
	// R6A-2: CurrentBootID's own error (e.g. /proc/sys/kernel/random/
	// boot_id unreadable) used to be silently discarded; it is now a
	// named audit record, since an operator trying to understand why
	// every enforcement bundle is being rejected needs to know whether
	// the cause was a stale probe (the branch below) or the agent
	// itself being unable to even determine the current boot. Either
	// way Load already fails closed (bootID == "" never matches a
	// facts file's own BootID), so this is diagnostics only -- it does
	// not change Load's fail-closed behavior.
	bootID, bootIDErr := hostprobe.CurrentBootID()
	if bootIDErr != nil {
		auditor.Record(agent.AuditEvent{Step: "host_facts_boot_id", Detail: "failed to read the current boot_id; host facts will be treated as stale until this succeeds", Err: bootIDErr})
	}
	hostCaps, fresh := hostprobe.Load(hostprobe.HostFactsPath, bootID)
	if !fresh {
		auditor.Record(agent.AuditEvent{Step: "host_facts", Detail: "host facts missing or stale; enforcement bundles will be rejected (REJECTED_CAPABILITY) once step 6b processes bundles"})
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

	engine := apply.NewEngine(tetraClient, apply.RealPolicyParser{}, startupResult.Store, noopReachability{}, &engineAuditorAdapter{auditor}, apply.Config{
		PersistDir: cfg.PersistDir,
		HealthWindow: apply.HealthWindowConfig{
			Window:         cfg.HealthWindow,
			SurgeThreshold: cfg.EnforcementSurgeThreshold,
		},
	})
	_ = engine // wired and ready for 6b's reconcile scheduling; not driven by this step

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

	snapshotProvider := &agent.RealSnapshotProvider{Store: startupResult.Store, Client: tetraClient, Scopes: cfg.AllowedScopes}
	controlLoop, err := agent.NewControlLoop(sm, auditor, time.Now, snapshotProvider, &agent.RealIdentityRotator{CertManager: certManager})
	if err != nil {
		cancelSession()
		return fmt.Errorf("new control loop: %w", err)
	}

	buildDigest, _ := agentBuildDigest() // best-effort; see buildHelloFields

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
		HeartbeatInterval: cfg.HeartbeatInterval,
	}

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

// noopReachability always reports the control plane as unreachable:
// Part C builds the apply.Engine but does not drive the control stream
// (see run's own doc comment), so there is nothing real to report yet.
// 6b's reconcile scheduling replaces this with a real
// apply.ReachabilityChecker backed by the control client's connection
// state.
type noopReachability struct{}

func (noopReachability) Reachable(context.Context) bool { return false }

// engineAuditorAdapter adapts agent.Auditor (Step/Detail/Err) to
// apply.Auditor (Step/Detail/Err/Domain/Policy): the two interfaces are
// structurally close but not identical (apply.AuditEvent carries two
// extra fields this adapter leaves zero), matching this project's
// existing convention of small, package-local adapters rather than
// unifying the two Auditor shapes across packages that are otherwise
// deliberately decoupled.
type engineAuditorAdapter struct {
	inner agent.Auditor
}

func (a *engineAuditorAdapter) Record(e apply.AuditEvent) {
	a.inner.Record(agent.AuditEvent{Step: e.Step, Detail: e.Detail, Err: e.Err})
}
