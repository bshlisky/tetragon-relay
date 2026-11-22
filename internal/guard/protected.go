package guard

import "strings"

// protectedBinaries is the compiled-in list from the step 2 prompt's Part
// C "Protected binaries" bullet, both usrmerge spellings. Each entry's
// comment records why it is protected.
var protectedBinaries = []string{
	"/usr/lib/systemd/systemd",           // PID 1 on a systemd host; killing it takes down every service
	"/sbin/init",                         // pre-usrmerge init path/symlink
	"/usr/sbin/init",                     // usrmerge init path
	"/usr/sbin/sshd",                     // remote admin access; losing it strands operators mid-incident
	"/sbin/sshd",                         // pre-usrmerge sshd path
	"/usr/bin/tetra",                     // Tetragon CLI; can itself add/delete TracingPolicies via the socket
	"/usr/local/bin/tetragon",            // common manual-install path for the Tetragon daemon
	"/usr/bin/tetragon",                  // packaged Tetragon daemon path
	"/usr/libexec/tetragon-relay/relayd", // the relay agent itself (architecture doc 3.1); killing it blinds policy delivery
	"/usr/sbin/chronyd",                  // time sync; losing it can desync cert/epoch validity windows (assumption A6)
	"/sbin/chronyd",                      // pre-usrmerge chronyd path
	"/usr/bin/spire-agent",               // host identity; losing it blocks re-enrollment/SVID renewal
	"/usr/lib/systemd/systemd-journald",  // local audit trail; killing it blinds forensics after an incident
	"/usr/bin/sudo",                      // privilege-escalation path operators rely on for break-glass access
	"/usr/sbin/auditd",                   // kernel audit daemon, part of the host hardening baseline (architecture doc 9.2)
	"/sbin/auditd",                       // pre-usrmerge auditd path
}

// protectedPaths is the compiled-in list from the step 2 prompt's Part C
// "Protected paths" bullet, normalized with path.Clean and the usrmerge
// aliases applied at comparison time (see normalizePathValue). Entries
// ending in "/" are directories; the rest are specific files/devices.
var protectedPaths = []string{
	"/var/run/tetragon/",
	"/run/tetragon/",
	"/etc/tetragon/",
	"/etc/tetragon-relay/",
	"/var/lib/tetragon-relay/",
	"/var/spool/tetragon-relay/",
	"/usr/libexec/tetragon-relay/",
	"/var/run/tetragon/tetragon.sock", // the Tetragon gRPC socket itself (architecture doc section 9.1); listed explicitly, not just its parent directory, so a Postfix match on its bare filename ("tetragon.sock") is caught by coversPostfix even though Postfix does not anchor to a directory
	"/dev/tpmrm0",
	"/dev/tpm0",
	"/sys/fs/bpf/",
}

// canonicalizeUsrmerge maps the pre-usrmerge short directory spellings to
// their RHEL 9 usrmerge (long) canonical form: /var/run is a symlink to
// /run, and /sbin, /bin are symlinks to /usr/sbin, /usr/bin. Both the
// compiled-in protected lists and every policy-supplied value are passed
// through this before comparison, so either spelling is caught.
func canonicalizeUsrmerge(p string) string {
	switch {
	case p == "/var/run" || strings.HasPrefix(p, "/var/run/"):
		return "/run" + p[len("/var/run"):]
	case p == "/sbin" || strings.HasPrefix(p, "/sbin/"):
		return "/usr/sbin" + p[len("/sbin"):]
	case p == "/bin" || strings.HasPrefix(p, "/bin/"):
		return "/usr/bin" + p[len("/bin"):]
	default:
		return p
	}
}
