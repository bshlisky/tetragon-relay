//go:build linux

package telemetry

import "syscall"

// Linux reports ru_maxrss in KiB (getrusage(2)).
func maxRSSBytes(r syscall.Rusage) int64 { return r.Maxrss * 1024 }
