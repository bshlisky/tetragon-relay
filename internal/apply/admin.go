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
