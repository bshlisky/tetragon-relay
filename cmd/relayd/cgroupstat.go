package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ownCPUStat returns relayd's own cgroup v2 usage_usec and nr_throttled
// (step-07b-decisions-3.md F0.2: the health window records whether relayd
// was throttled while it watched). Read-only: /proc/self/cgroup (allowed
// under ProcSubset=pid) and the cgroup's cpu.stat (ProtectControlGroups
// mounts /sys/fs/cgroup read-only, which is enough).
func ownCPUStat() (usageUsec, nrThrottled uint64, err error) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, 0, err
	}
	path, err := cgroupV2Path(raw)
	if err != nil {
		return 0, 0, err
	}
	stat, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", path, "cpu.stat")) //nolint:gosec // G304: our own cgroup's cpu.stat
	if err != nil {
		return 0, 0, err
	}
	return parseCPUStat(stat)
}

// cgroupV2Path extracts the unified-hierarchy path ("0::<path>").
func cgroupV2Path(raw []byte) (string, error) {
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			p = filepath.Clean("/" + p)
			if strings.Contains(p, "..") {
				return "", fmt.Errorf("cgroup path %q", p)
			}
			return p, nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in /proc/self/cgroup")
}

func parseCPUStat(stat []byte) (usageUsec, nrThrottled uint64, err error) {
	var haveU, haveT bool
	sc := bufio.NewScanner(bytes.NewReader(stat))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		v, perr := strconv.ParseUint(f[1], 10, 64)
		if perr != nil {
			continue
		}
		switch f[0] {
		case "usage_usec":
			usageUsec, haveU = v, true
		case "nr_throttled":
			nrThrottled, haveT = v, true
		}
	}
	if !haveU || !haveT {
		return 0, 0, fmt.Errorf("cpu.stat lacks usage_usec or nr_throttled")
	}
	return usageUsec, nrThrottled, nil
}
