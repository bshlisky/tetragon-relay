// Package hostprobe implements step 3 prompt Part C4: the agent-side half
// of the host capability probe. cmd/relay-probe (run as root by systemd
// before the agent starts, ExecStartPre=+...) gathers host facts requiring
// root and writes them to HostFactsPath; this package reads that file back
// (as the unprivileged agent) and turns it into a guard.HostCapabilities,
// failing closed (every capability false, enforcement bundles rejected) on
// any problem: missing file, unparseable JSON, unsupported schema version,
// or a boot_id that does not match the current boot (the facts predate a
// reboot and may no longer be accurate for the running kernel).
package hostprobe

import "time"

// HostFactsSchemaVersion is bumped whenever HostFacts's shape changes in a
// way old readers must not silently misinterpret. LoadHostCapabilities
// rejects any other value outright rather than guessing at compatibility.
//
// 2: tetragon_env_collection and tetragon_env_collection_source
// (step-07b-decisions-3.md F4).
const HostFactsSchemaVersion = 2

// HostFactsPath is the default path cmd/relay-probe writes to and
// LoadHostCapabilities reads from (step 3 prompt Part C4).
const HostFactsPath = "/run/tetragon-relay/host-facts.json"

// ErrorInjectionUnknown is the sentinel ErrorInjectionList value used when
// debugfs is not mounted and the error-injection list genuinely cannot be
// read (step 3 prompt Part C1: "else record 'unknown' and treat
// KprobeOverride as false").
const ErrorInjectionUnknown = "unknown"

// TetragonEnvCollection values (step-07b-decisions-3.md F4): whether the
// running Tetragon collects process environment variables
// (--enable-process-environment-variables).
const (
	EnvCollectionOn      = "on"
	EnvCollectionOff     = "off"
	EnvCollectionUnknown = "unknown"
)

// HostFacts is the versioned schema cmd/relay-probe writes to
// HostFactsPath and this package reads back. Field names are the stable,
// on-disk JSON contract between the two: changing one without bumping
// SchemaVersion is a bug.
type HostFacts struct {
	// SchemaVersion must equal HostFactsSchemaVersion for this file to be
	// trusted at all.
	SchemaVersion int `json:"schema_version"`
	// GeneratedAt is when relay-probe produced this file (informational;
	// BootID, not this timestamp, is what staleness is judged against).
	GeneratedAt time.Time `json:"generated_at"`
	// BootID is /proc/sys/kernel/random/boot_id at probe time. Part C4:
	// facts "older than the current boot_id" (i.e. BootID does not match
	// the running kernel's current boot_id) must be treated as missing.
	BootID string `json:"boot_id"`

	// KernelRelease is uname -r.
	KernelRelease string `json:"kernel_release"`
	// RHELRelease is the content of /etc/redhat-release (or equivalent),
	// trimmed.
	RHELRelease string `json:"rhel_release"`

	// KprobeOverride reports whether Override is usable on kprobes:
	// CONFIG_BPF_KPROBE_OVERRIDE and CONFIG_FUNCTION_ERROR_INJECTION
	// (via /proc/config.gz or /boot/config-$(uname -r)) are both set,
	// AND the error-injection list (debugfs) was actually readable
	// (Part C1: unreadable/unmounted debugfs forces this to false
	// regardless of the two kconfig bits, since neither bit alone proves
	// a specific target function is override-able).
	KprobeOverride bool `json:"kprobe_override"`
	// LSMBPF reports whether CONFIG_BPF_LSM is set AND "bpf" appears in
	// /sys/kernel/security/lsm's active list.
	LSMBPF bool `json:"lsm_bpf"`
	// ErrorInjectionSource records where ErrorInjectionList came from:
	// "debugfs" or ErrorInjectionUnknown.
	ErrorInjectionSource string `json:"error_injection_source"`
	// ErrorInjectionList is the raw list of override-able functions, or
	// nil if ErrorInjectionSource is ErrorInjectionUnknown.
	ErrorInjectionList []string `json:"error_injection_list,omitempty"`

	// UsrmergeOK reports whether every usrmerge symlink Part C2 checks
	// (/bin, /sbin, /lib, /lib64 -> usr/*, /var/run -> ../run) matches
	// its expected target exactly. false means the agent must refuse to
	// apply enforcement bundles (monitor mode is still allowed), since
	// the guardrails' protected-path spellings assume usrmerge.
	UsrmergeOK bool `json:"usrmerge_ok"`
	// UsrmergeDetail explains a false UsrmergeOK (which link, what was
	// found instead), empty when UsrmergeOK is true.
	UsrmergeDetail string `json:"usrmerge_detail,omitempty"`

	// SecureBoot reports whether UEFI Secure Boot is enabled.
	SecureBoot bool `json:"secure_boot"`
	// LockdownMode is the kernel lockdown mode: "none", "integrity",
	// "confidentiality", or "unknown" if unreadable.
	LockdownMode string `json:"lockdown_mode"`
	// SELinuxMode is "enforcing", "permissive", or "disabled".
	SELinuxMode string `json:"selinux_mode"`

	// TetragonBinaryPath is the configured Tetragon binary path that was
	// hashed to produce TetragonBinarySHA256.
	TetragonBinaryPath string `json:"tetragon_binary_path"`
	// TetragonBinarySHA256 is the sha256 of the file at
	// TetragonBinaryPath at probe time, hex-encoded.
	TetragonBinarySHA256 string `json:"tetragon_binary_sha256"`

	// TetragonEnvCollection is EnvCollectionOn, EnvCollectionOff or
	// EnvCollectionUnknown: whether the running Tetragon was started with
	// process environment collection (its flag, environment variable or
	// configuration file; F4). Production ships without it; "on" is a
	// privacy finding, not an enforcement one.
	TetragonEnvCollection string `json:"tetragon_env_collection"`
	// TetragonEnvCollectionSource says where the value came from (e.g.
	// "flag", "env", "conf.d:/etc/tetragon/tetragon.conf.d", "default",
	// or why it is unknown).
	TetragonEnvCollectionSource string `json:"tetragon_env_collection_source,omitempty"`
}
