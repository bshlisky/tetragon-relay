//go:build !linux

package telemetry

import "syscall"

// Darwin reports ru_maxrss in bytes (getrusage(2) on macOS).
func maxRSSBytes(r syscall.Rusage) int64 { return r.Maxrss }
