package apply

// adminPathBinaries is step 3 prompt Part D5's admin-path set, both
// usrmerge spellings (mirroring internal/guard/protected.go's convention
// for the same reason: this project does not assume which spelling a
// given binary resolves through on every RHEL 9 build). Architect review
// R2D-1 / design note DN-1 (docs/reviews/step-02d-review.md) is why this
// exists: G1 cannot protect every shell without rejecting legitimate
// policies that target bash/sh for non-admin reasons, so instead the
// apply engine's health window treats a kill of any of these (or any
// ancestor of the killed process being one of these) as a rollback
// trigger.
//
// Caller semantics (step-03a-review.md R3-E3, ADR 0020): for a
// `security_bprm_check` kprobe (the hook internal/apply's own canary
// policies use, and a plausible one for a real enforce-mode policy to
// hook), Tetragon's reported process/matchBinaries describe the CALLER of
// exec — the process about to replace its own image — not the new binary
// being loaded. A policy whose matchBinaries lists one of these paths
// therefore fires when that binary itself execs something while loaded,
// not when something else execs that binary; this is still the correct
// detection for this package's purpose (a malicious policy killing an
// admin's shell mid-session, which fires exactly when that shell is about
// to run the next command), it is just not "kills X" in the naive sense
// of X being the new image. internal/apply/integration_test.go's own
// admin-path test targets a private copy of bash at /tmp/testbin/bash
// precisely because of this: the test must exec something FROM that
// binary to trigger the hook at all, and must never do so from the real
// /usr/bin/bash (which is also whatever shell is running the test).
var adminPathBinaries = map[string]bool{
	"/usr/sbin/sshd":                     true,
	"/sbin/sshd":                         true,
	"/usr/libexec/openssh/sshd-session":  true,
	"/usr/bin/bash":                      true,
	"/bin/bash":                          true,
	"/usr/bin/sh":                        true,
	"/bin/sh":                            true,
	"/usr/bin/zsh":                       true,
	"/bin/zsh":                           true,
	"/usr/bin/dash":                      true,
	"/bin/dash":                          true,
	"/usr/bin/login":                     true,
	"/bin/login":                         true,
	"/usr/bin/su":                        true,
	"/bin/su":                            true,
	"/usr/bin/sudo":                      true,
	"/bin/sudo":                          true,
	"/usr/lib/systemd/systemd-logind":    true,
	"/usr/libexec/tetragon-relay/relayd": true,
	"/usr/local/bin/tetragon":            true,
	"/usr/bin/tetragon":                  true,
	"/bin/tetragon":                      true,
	"/usr/bin/spire-agent":               true,
	"/bin/spire-agent":                   true,
}

// isAdminPathBinary reports whether path is in adminPathBinaries.
func isAdminPathBinary(path string) bool { return adminPathBinaries[path] }
