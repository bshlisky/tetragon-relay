//go:build linux

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/bshlisky/tetragon-relay/internal/hostprobe"
)

// secureBootGUID is the well-known EFI global variable GUID under which
// SecureBoot is published (efivarfs), per the UEFI spec.
const secureBootEFIVar = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

// openKconfig implements step 3 prompt Part C1's kernel config source
// order: /proc/config.gz (gzip-compressed) if present, else
// /boot/config-$(uname -r) (plain text).
func openKconfig(kernelRelease string) (io.ReadCloser, error) {
	if f, err := os.Open("/proc/config.gz"); err == nil { //nolint:gosec // fixed, well-known path
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			_ = f.Close()
			return nil, gerr
		}
		return struct {
			io.Reader
			io.Closer
		}{gz, f}, nil
	}
	path := "/boot/config-" + kernelRelease
	f, err := os.Open(path) //nolint:gosec // kernelRelease comes from uname(2), not attacker input
	if err != nil {
		return nil, fmt.Errorf("neither /proc/config.gz nor %s is readable: %w", path, err)
	}
	return f, nil
}

func readKernelRelease() (string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	n := bytes.IndexByte(uts.Release[:], 0)
	if n < 0 {
		n = len(uts.Release)
	}
	return string(uts.Release[:n]), nil
}

func readRHELRelease() string {
	for _, p := range []string{"/etc/redhat-release", "/etc/system-release"} {
		if data, err := os.ReadFile(p); err == nil { //nolint:gosec // fixed, well-known paths
			return strings.TrimSpace(string(data))
		}
	}
	return "unknown"
}

func readActiveLSMs() []string {
	data, err := os.ReadFile("/sys/kernel/security/lsm") //nolint:gosec // fixed, well-known path
	if err != nil {
		return nil
	}
	return parseActiveLSMs(string(data))
}

func readLockdownMode() string {
	data, err := os.ReadFile("/sys/kernel/security/lockdown") //nolint:gosec // fixed, well-known path
	if err != nil {
		return "unknown"
	}
	return parseLockdownMode(string(data))
}

func readSELinuxMode() string {
	data, err := os.ReadFile("/sys/fs/selinux/enforce") //nolint:gosec // fixed, well-known path
	if err != nil {
		// /sys/fs/selinux does not exist at all when SELinux is disabled
		// in the running kernel (not merely permissive).
		return "disabled"
	}
	if strings.TrimSpace(string(data)) == "1" {
		return "enforcing"
	}
	return "permissive"
}

// readSecureBoot reads the UEFI SecureBoot efivarfs variable. Its content
// is a 4-byte little-endian attributes word followed by a 1-byte value (1
// = enabled). Absence of the file (BIOS/legacy boot, or efivarfs not
// mounted) is reported as false: Secure Boot cannot be "enabled" if the
// firmware does not even expose the concept.
func readSecureBoot() bool {
	data, err := os.ReadFile(secureBootEFIVar) //nolint:gosec // fixed, well-known path
	if err != nil || len(data) < 5 {
		return false
	}
	return data[4] == 1
}

func readErrorInjectionList() ([]string, string) {
	f, err := os.Open("/sys/kernel/debug/error_injection/list") //nolint:gosec // fixed, well-known path
	if err != nil {
		return nil, hostprobe.ErrorInjectionUnknown
	}
	defer func() { _ = f.Close() }()
	return parseErrorInjectionList(f), "debugfs"
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path is operator-configured (architecture doc 8.6), not attacker-controlled
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// collect implements step 3 prompt Parts C1-C3 for real, on Linux.
func collect(tetragonBinaryPath string) (*hostprobe.HostFacts, error) {
	kernelRelease, err := readKernelRelease()
	if err != nil {
		return nil, fmt.Errorf("uname: %w", err)
	}

	kc, err := openKconfig(kernelRelease)
	if err != nil {
		return nil, err
	}
	cfg := parseKconfig(kc)
	_ = kc.Close()

	errInjList, errInjSource := readErrorInjectionList()
	lsms := readActiveLSMs()

	kprobeOverride := kconfigSet(cfg, "CONFIG_BPF_KPROBE_OVERRIDE") &&
		kconfigSet(cfg, "CONFIG_FUNCTION_ERROR_INJECTION") &&
		errInjSource == "debugfs"
	lsmBPF := kconfigSet(cfg, "CONFIG_BPF_LSM") && containsLSM(lsms, "bpf")

	usrmergeOK, usrmergeDetail := checkUsrmerge(os.Readlink)

	bootID, err := hostprobe.CurrentBootID()
	if err != nil {
		return nil, fmt.Errorf("boot_id: %w", err)
	}

	sha, err := sha256File(tetragonBinaryPath)
	if err != nil {
		return nil, fmt.Errorf("hash Tetragon binary %s: %w", tetragonBinaryPath, err)
	}

	return &hostprobe.HostFacts{
		SchemaVersion:        hostprobe.HostFactsSchemaVersion,
		BootID:               bootID,
		KernelRelease:        kernelRelease,
		RHELRelease:          readRHELRelease(),
		KprobeOverride:       kprobeOverride,
		LSMBPF:               lsmBPF,
		ErrorInjectionSource: errInjSource,
		ErrorInjectionList:   errInjList,
		UsrmergeOK:           usrmergeOK,
		UsrmergeDetail:       usrmergeDetail,
		SecureBoot:           readSecureBoot(),
		LockdownMode:         readLockdownMode(),
		SELinuxMode:          readSELinuxMode(),
		TetragonBinaryPath:   tetragonBinaryPath,
		TetragonBinarySHA256: sha,
	}, nil
}
