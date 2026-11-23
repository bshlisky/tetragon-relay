//go:build linux

package hostprobe

import (
	"os"
	"strings"
)

// bootIDPath is a package variable (not a literal inline in currentBootID)
// purely so tests can point it at a nonexistent path to exercise the error
// branch deterministically, without needing to tamper with a real
// /proc/sys/kernel/random/boot_id (which always exists and is readable on
// any real Linux CI runner).
var bootIDPath = "/proc/sys/kernel/random/boot_id"

func currentBootID() (string, error) {
	data, err := os.ReadFile(bootIDPath) //nolint:gosec // bootIDPath is a fixed, well-known path (or a test-injected override), not attacker-controlled
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
