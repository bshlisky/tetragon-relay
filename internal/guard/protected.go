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
	"/bin/tetra",                         // pre-usrmerge /usr/bin alias
	"/usr/local/bin/tetragon",            // common manual-install path for the Tetragon daemon
	"/usr/bin/tetragon",                  // packaged Tetragon daemon path
	"/bin/tetragon",                      // pre-usrmerge /usr/bin alias
	"/usr/libexec/tetragon-relay/relayd", // the relay agent itself (architecture doc 3.1); killing it blinds policy delivery
	"/usr/sbin/chronyd",                  // time sync; losing it can desync cert/epoch validity windows (assumption A6)
	"/sbin/chronyd",                      // pre-usrmerge chronyd path
	"/usr/bin/spire-agent",               // host identity; losing it blocks re-enrollment/SVID renewal
	"/bin/spire-agent",                   // pre-usrmerge /usr/bin alias
	"/usr/lib/systemd/systemd-journald",  // local audit trail; killing it blinds forensics after an incident
	"/usr/bin/sudo",                      // privilege-escalation path operators rely on for break-glass access
	"/bin/sudo",                          // pre-usrmerge /usr/bin alias
	"/usr/sbin/auditd",                   // kernel audit daemon, part of the host hardening baseline (architecture doc 9.2)
	"/sbin/auditd",                       // pre-usrmerge auditd path
	"/usr/libexec/openssh/sshd-session",  // OpenSSH's post-9.8 per-session re-exec target; killing it drops active/incoming sessions same as sshd itself
	"/usr/lib/systemd/systemd-logind",    // manages login sessions/seats; killing it can lock out console and some remote login paths
}

// protectedPaths is the compiled-in list from the step 2 prompt's Part C
// "Protected paths" bullet, both usrmerge spellings listed explicitly as
// separate entries (see usrmergeAlias, checked by a test against this list
// rather than applied as a runtime transform — architect review item C1
// found that canonicalizing selector values to one spelling and comparing
// against literal, unconverted list entries silently broke matching for
// the spelling that wasn't converted to). Entries ending in "/" are
// directories (matched by pathCoversPositive's directory-aware formula,
// architect review item C2); the rest are specific files/devices (matched
// like a protected binary, via matches()).
var protectedPaths = []string{
	"/var/run/tetragon/",
	"/run/tetragon/",
	"/etc/tetragon/",
	"/etc/tetragon-relay/",
	"/var/lib/tetragon-relay/",
	"/var/spool/tetragon-relay/",
	"/usr/libexec/tetragon-relay/",
	"/var/run/tetragon/tetragon.sock", // the Tetragon gRPC socket itself (architecture doc section 9.1); listed explicitly, not just its parent directory, so a Postfix match on its bare filename ("tetragon.sock") is still caught (pathCoversPositive treats it as an exact-file target, decidable via matches() directly)
	"/run/tetragon/tetragon.sock",     // usrmerge spelling of the line above
	"/dev/tpmrm0",
	"/dev/tpm0",
	"/sys/fs/bpf/",
}

// usrmergeAlias maps the pre-usrmerge short directory spellings to their
// RHEL 9 usrmerge (long) canonical form: /var/run is a symlink to /run,
// and /sbin, /bin are symlinks to /usr/sbin, /usr/bin. Used only by
// TestProtectedLists_BothUsrmergeSpellingsPresent to verify every
// protected binary/path that has a usrmerge-aliasable prefix is listed
// under both spellings; matching itself (paths.go) relies purely on the
// list already containing both literal spellings as separate candidates,
// not on converting values at match time (see the protectedPaths doc
// comment above for why the latter is a correctness trap).
func usrmergeAlias(p string) (string, bool) {
	switch {
	case strings.HasPrefix(p, "/var/run/"):
		return "/run" + p[len("/var/run"):], true
	case strings.HasPrefix(p, "/sbin/"):
		return "/usr/sbin" + p[len("/sbin"):], true
	case strings.HasPrefix(p, "/bin/"):
		return "/usr/bin" + p[len("/bin"):], true
	case strings.HasPrefix(p, "/run/"):
		return "/var/run" + p[len("/run"):], true
	case strings.HasPrefix(p, "/usr/sbin/"):
		return "/sbin" + p[len("/usr/sbin"):], true
	case strings.HasPrefix(p, "/usr/bin/"):
		return "/bin" + p[len("/usr/bin"):], true
	default:
		return "", false
	}
}
