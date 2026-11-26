//go:build linux

package hostprobe

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// platformStatOpenFile reads type, owner and mode with fstat, and the
// filesystem type with fstatfs, both on the already-open descriptor.
func platformStatOpenFile(f *os.File) (fileInfo, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil { //nolint:gosec // G115: a file descriptor always fits in int
		return fileInfo{}, fmt.Errorf("%w: fstat: %w", ErrHostFactsUnreadable, err)
	}
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &sfs); err != nil { //nolint:gosec // G115: as above
		return fileInfo{}, fmt.Errorf("%w: fstatfs: %w", ErrHostFactsUnreadable, err)
	}
	return fileInfo{
		regular: st.Mode&unix.S_IFMT == unix.S_IFREG,
		uid:     st.Uid,
		perm:    os.FileMode(st.Mode&0o7777).Perm() | specialBits(st.Mode),
		onTmpfs: int64(sfs.Type) == int64(unix.TMPFS_MAGIC), //nolint:unconvert // Statfs_t.Type's width differs by architecture
	}, nil
}

// specialBits maps setuid/setgid/sticky into fs.FileMode bits, so a
// 0640 file with any of them set does not compare equal to HostFactsMode.
func specialBits(mode uint32) os.FileMode {
	var m os.FileMode
	if mode&unix.S_ISUID != 0 {
		m |= os.ModeSetuid
	}
	if mode&unix.S_ISGID != 0 {
		m |= os.ModeSetgid
	}
	if mode&unix.S_ISVTX != 0 {
		m |= os.ModeSticky
	}
	return m
}
