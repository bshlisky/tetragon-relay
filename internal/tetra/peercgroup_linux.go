//go:build linux

package tetra

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// cgroupRoot is cgroup v2's single mount point. Architecture doc section
// 9.2 requires RHEL 9 (cgroup v2 unified hierarchy by default since
// RHEL 8/systemd 219+); unlike cgroup v1's multiple per-controller mount
// points, the unified hierarchy has exactly one, so this is not
// configurable.
const cgroupRoot = "/sys/fs/cgroup"

// maxCgroupProcsBytes bounds the cgroup.procs read (step-03a-review.md
// R3-1 amendment: "bounded read size (e.g. 1 MiB)"). A real Tetragon unit
// cgroup holds a handful of pids; this is far more than any legitimate
// file while still bounding the read against a crafted or malfunctioning
// one.
const maxCgroupProcsBytes = 1 << 20

// statfsFunc is a package variable so tests can stub the cgroup v2
// detection without needing a specific host filesystem layout, mirroring
// getxattrFunc/peerCredFunc/getsockoptPeerSecFunc's pattern in
// dial_linux.go.
var statfsFunc = unix.Statfs

// isCgroupV2 reports whether cgroupRoot is mounted as the cgroup v2
// unified hierarchy: statfs's f_type equals CGROUP2_SUPER_MAGIC
// (Documentation/admin-guide/cgroup-v2.rst, "Mounting": "cgroup2
// filesystem has the magic number 0x63677270 (CGROUP2_SUPER_MAGIC)").
func isCgroupV2() (bool, error) {
	var st unix.Statfs_t
	if err := statfsFunc(cgroupRoot, &st); err != nil {
		return false, err
	}
	return st.Type == unix.CGROUP2_SUPER_MAGIC, nil
}

// readCgroupProcsFunc is a package variable so tests can stub the
// cgroup.procs read itself (wrong cgroup, empty file, malformed line,
// unreadable file, symlink-in-place) without a real cgroupfs.
var readCgroupProcsFunc = readCgroupProcsFile

// readCgroupProcsFile parses path (a cgroup v2 "cgroup.procs" file:
// Documentation/admin-guide/cgroup-v2.rst, "Organizing Processes and
// Threads": "lists the PIDs of all processes which belong to the cgroup
// one-per-line") into a pid set. It lstats first and refuses a symlink
// (the review's "no symlink following" requirement — cgroupfs entries are
// kernel-created, not expected to ever be a symlink, so one indicates a
// tampered or unexpected layout) and bounds the read at
// maxCgroupProcsBytes.
func readCgroupProcsFile(path string) (map[int32]bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink", path)
	}
	f, err := os.Open(path) //nolint:gosec // path is cgroupRoot joined with Config.UnitCgroupPath (deployment-configured, architecture doc 8.6), not attacker-controlled; lstat above already rejected a symlink
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	out := make(map[int32]bool)
	scanner := bufio.NewScanner(io.LimitReader(f, maxCgroupProcsBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		pid, err := strconv.ParseInt(line, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%s: malformed line %q: %w", path, line, err)
		}
		out[int32(pid)] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return out, nil
}

// cgroupCheckResult is verifyPeerCgroup's outcome. Available is false only
// when the check could not run at all (cgroup v1/hybrid layout); it is
// true (with Passed reflecting the actual membership test) for every
// cgroup v2 host, including a wrong-cgroup result, which is a definite
// failure, not an "unavailable" one.
type cgroupCheckResult struct {
	Available bool
	Passed    bool
}

// verifyPeerCgroup implements the step-03a-review.md R3-1 amendment: the
// connected peer's pid (from SO_PEERCRED) must appear in
// cgroupRoot/<Config.UnitCgroupPath>/cgroup.procs. Unlike the original
// review text's /proc/<peer pid>/cgroup, this never reads anything under
// /proc, so it is unaffected by the production unit's
// ProtectProc=invisible (packaging/systemd/tetragon-relay.service):
// systemd.exec(5) ProtectProc=: "the root user is unaffected by this
// option, so to be effective it has to be used together with User=...
// and also without the CAP_SYS_PTRACE capability" — once CAP_SYS_PTRACE
// is removed (R3-1), hidepid=invisible hides Tetragon's root-owned
// /proc/<pid> from this unit entirely. ProtectControlGroups=yes, by
// contrast, only mounts /sys/fs/cgroup read-only (systemd
// src/core/namespace.c's protect_control_groups_yes_table); it does not
// hide or namespace it, so cgroupRoot stays at its normal global path and
// stays readable.
func verifyPeerCgroup(cfg Config, pid int32) (cgroupCheckResult, error) {
	v2, err := isCgroupV2()
	if err != nil {
		return cgroupCheckResult{}, fmt.Errorf("%w: statfs %s: %w", ErrSocketVerification, cgroupRoot, err)
	}
	if !v2 {
		// cgroup v1 or a hybrid layout: the amendment tolerates this
		// (caller falls back to requiring the SO_PEERSEC check to have
		// actively passed) rather than treating it as a hard failure.
		return cgroupCheckResult{Available: false}, nil
	}
	pids, err := readCgroupProcsFunc(cgroupRoot + "/" + cfg.unitCgroupPath() + "/cgroup.procs")
	if err != nil {
		return cgroupCheckResult{}, fmt.Errorf("%w: %w", ErrSocketVerification, err)
	}
	return cgroupCheckResult{Available: true, Passed: pids[pid]}, nil
}
