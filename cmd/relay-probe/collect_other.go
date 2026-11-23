//go:build !linux

package main

import (
	"fmt"
	"runtime"

	"github.com/bshlisky/tetragon-relay/internal/hostprobe"
)

// collect is only implemented on linux: every fact it gathers (kernel
// config, /sys/kernel/security/*, efivarfs, SELinux) is Linux-specific,
// and architecture doc section 1.1 scopes this project to RHEL 9. This
// stub exists only so cmd/relay-probe builds and vets on a non-Linux
// development machine.
func collect(string) (*hostprobe.HostFacts, error) {
	return nil, fmt.Errorf("relay-probe: collect is only implemented on linux (GOOS=%s)", runtime.GOOS)
}
