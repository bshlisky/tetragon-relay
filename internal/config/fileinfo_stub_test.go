package config

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

// fileInfoStub is a synthetic os.FileInfo used to unit-test
// validateConfigFileInfo/validateParentDirInfo's owner/group branches
// without needing a real root-owned or tetragon-relay-group-owned file:
// those branches would otherwise only be exercisable by running the test
// suite as root (see load.go's doc comment on validateConfigFileInfo).
type fileInfoStub struct {
	mode  os.FileMode
	isDir bool
	sys   interface{}
}

func (f fileInfoStub) Name() string       { return "stub" }
func (f fileInfoStub) Size() int64        { return 0 }
func (f fileInfoStub) Mode() os.FileMode  { return f.mode }
func (f fileInfoStub) ModTime() time.Time { return time.Time{} }
func (f fileInfoStub) IsDir() bool        { return f.isDir }
func (f fileInfoStub) Sys() interface{}   { return f.sys }

func statT64(uid, gid uint32) *syscall.Stat_t {
	return &syscall.Stat_t{Uid: uid, Gid: gid} //nolint:unconvert // field widths differ across platforms; literal construction here, not a conversion
}

func TestValidateConfigFileInfo_AllBranches(t *testing.T) {
	rootOwned := statT64(0, 100)
	tests := []struct {
		name     string
		fi       fileInfoStub
		groupGID uint32
		groupErr error
		wantErr  error
	}{
		{"symlink", fileInfoStub{mode: os.ModeSymlink | 0o640, sys: rootOwned}, 100, nil, ErrConfigIsSymlink},
		{"not regular (dir bit)", fileInfoStub{mode: os.ModeDir | 0o640, sys: rootOwned}, 100, nil, ErrConfigNotRegularFile},
		{"mode too permissive", fileInfoStub{mode: 0o644, sys: rootOwned}, 100, nil, ErrConfigModeTooPermissive},
		{"cannot verify ownership", fileInfoStub{mode: 0o640, sys: "not a Stat_t"}, 100, nil, ErrConfigCannotVerifyOwnership},
		{"not owned by root", fileInfoStub{mode: 0o640, sys: statT64(1000, 100)}, 100, nil, ErrConfigNotOwnedByRoot},
		{"group lookup failed", fileInfoStub{mode: 0o640, sys: rootOwned}, 0, errGroupNotFoundForTest, ErrConfigGroupLookupFailed},
		{"wrong group", fileInfoStub{mode: 0o640, sys: rootOwned}, 999, nil, ErrConfigWrongGroup},
		{"accepted", fileInfoStub{mode: 0o640, sys: rootOwned}, 100, nil, nil},
		{"accepted at a stricter mode", fileInfoStub{mode: 0o400, sys: rootOwned}, 100, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withGroupLookup(t, tc.groupGID, tc.groupErr)
			err := validateConfigFileInfo(tc.fi, "/etc/tetragon-relay/relay.yaml")
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("validateConfigFileInfo: %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
