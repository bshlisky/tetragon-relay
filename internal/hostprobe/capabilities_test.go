package hostprobe

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validFacts(bootID string) *HostFacts {
	return &HostFacts{
		SchemaVersion:        HostFactsSchemaVersion,
		GeneratedAt:          time.Now(),
		BootID:               bootID,
		KernelRelease:        "5.14.0-500.el9.x86_64",
		RHELRelease:          "Red Hat Enterprise Linux release 9.4",
		KprobeOverride:       true,
		LSMBPF:               true,
		ErrorInjectionSource: "debugfs",
		ErrorInjectionList:   []string{"security_file_open"},
		UsrmergeOK:           true,
		SecureBoot:           true,
		LockdownMode:         "integrity",
		SELinuxMode:          "enforcing",
		TetragonBinaryPath:   "/usr/local/bin/tetragon",
		TetragonBinarySHA256: "deadbeef",
	}
}

func writeFacts(t *testing.T, dir string, f *HostFacts) string {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "host-facts.json")
	if err := os.WriteFile(p, data, 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

// goodStat is what platformStatOpenFile reports for the file
// cmd/relay-probe writes under /run in production.
var goodStat = fileInfo{regular: true, uid: 0, perm: HostFactsMode, onTmpfs: true}

// withStat makes Load see info for every file it opens in this test, so
// each branch of ADR 0034's freshness rule is testable without root or
// tmpfs. TestPlatformStatOpenFile_Linux covers the real fstat/fstatfs.
func withStat(t *testing.T, info fileInfo) {
	t.Helper()
	restore := statOpenFile
	statOpenFile = func(*os.File) (fileInfo, error) { return info, nil }
	t.Cleanup(func() { statOpenFile = restore })
}

func TestLoad_Valid(t *testing.T) {
	withStat(t, goodStat)
	p := writeFacts(t, t.TempDir(), validFacts("boot-a"))

	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.KprobeOverride() || !c.LSMBPF() || !c.UsrmergeOK() {
		t.Fatalf("capabilities not reported as available: %+v", c)
	}
	facts, ok := c.Facts()
	if !ok || facts.KernelRelease != "5.14.0-500.el9.x86_64" || facts.BootID != "boot-a" {
		t.Fatalf("Facts() = %+v, %v", facts, ok)
	}
}

func TestLoad_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeRaw := func(t *testing.T, name, raw string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(raw), 0o640); err != nil {
			t.Fatal(err)
		}
		return p
	}
	valid := writeFacts(t, dir, validFacts("boot-a"))
	wrongSchema := validFacts("boot-a")
	wrongSchema.SchemaVersion = 999
	noBoot := validFacts("")

	cases := []struct {
		name string
		stat fileInfo
		path string
		want error
	}{
		{"missing_file", goodStat, filepath.Join(dir, "does-not-exist.json"), ErrHostFactsUnreadable},
		{"not_regular", fileInfo{regular: false, uid: 0, perm: HostFactsMode, onTmpfs: true}, valid, ErrHostFactsNotRegular},
		{"not_tmpfs", fileInfo{regular: true, uid: 0, perm: HostFactsMode, onTmpfs: false}, valid, ErrHostFactsNotTmpfs},
		{"not_root_owned", fileInfo{regular: true, uid: 1000, perm: HostFactsMode, onTmpfs: true}, valid, ErrHostFactsOwner},
		{"mode_0644", fileInfo{regular: true, uid: 0, perm: 0o644, onTmpfs: true}, valid, ErrHostFactsMode},
		{"mode_setgid", fileInfo{regular: true, uid: 0, perm: HostFactsMode | os.ModeSetgid, onTmpfs: true}, valid, ErrHostFactsMode},
		{"wrong_schema_version", goodStat, writeFacts(t, t.TempDir(), wrongSchema), ErrHostFactsSchema},
		{"empty_boot_id", goodStat, writeFacts(t, t.TempDir(), noBoot), ErrHostFactsNoBootID},
		{"corrupt_json", goodStat, writeRaw(t, "corrupt.json", "{not valid json"), ErrHostFactsMalformed},
		{"duplicate_key_rejected", goodStat, writeRaw(t, "dup.json", `{"schema_version":1,"boot_id":"boot-a","boot_id":"boot-b"}`), ErrHostFactsMalformed},
		{"unknown_field_rejected", goodStat, writeRaw(t, "unknown.json", `{"schema_version":1,"boot_id":"boot-a","totally_unknown_field":true}`), ErrHostFactsMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withStat(t, tc.stat)
			c, err := Load(tc.path)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Load error = %v, want %v", err, tc.want)
			}
			assertFailClosed(t, c)
		})
	}

	t.Run("read_error", func(t *testing.T) {
		// A directory passes the (faked) stat rule but fails the read.
		withStat(t, goodStat)
		c, err := Load(t.TempDir())
		if !errors.Is(err, ErrHostFactsUnreadable) {
			t.Fatalf("Load(dir) error = %v, want ErrHostFactsUnreadable", err)
		}
		assertFailClosed(t, c)
	})

	t.Run("stat_error", func(t *testing.T) {
		restore := statOpenFile
		statOpenFile = func(*os.File) (fileInfo, error) { return fileInfo{}, ErrHostFactsUnreadable }
		t.Cleanup(func() { statOpenFile = restore })
		c, err := Load(valid)
		if !errors.Is(err, ErrHostFactsUnreadable) {
			t.Fatalf("Load error = %v, want ErrHostFactsUnreadable", err)
		}
		assertFailClosed(t, c)
	})

	t.Run("symlink_not_followed", func(t *testing.T) {
		withStat(t, goodStat)
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(valid, link); err != nil {
			t.Fatal(err)
		}
		c, err := Load(link)
		if !errors.Is(err, ErrHostFactsUnreadable) {
			t.Fatalf("Load(symlink) error = %v, want ErrHostFactsUnreadable (O_NOFOLLOW)", err)
		}
		assertFailClosed(t, c)
	})
}

func assertFailClosed(t *testing.T, c *Capabilities) {
	t.Helper()
	if c.KprobeOverride() {
		t.Error("KprobeOverride() true for a fail-closed Capabilities")
	}
	if c.LSMBPF() {
		t.Error("LSMBPF() true for a fail-closed Capabilities")
	}
	if c.UsrmergeOK() {
		t.Error("UsrmergeOK() true for a fail-closed Capabilities")
	}
	if _, ok := c.Facts(); ok {
		t.Error("Facts() ok=true for a fail-closed Capabilities")
	}
}

func TestParse_EmptyInput(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("Parse(nil) did not error")
	}
	if _, err := Parse([]byte{}); err == nil {
		t.Fatal("Parse(\"\") did not error")
	}
}

func TestCurrentBootID_ErrorIsNonFatal(t *testing.T) {
	t.Helper()
	// Only asserts the call does not panic; behavior is platform
	// dependent (linux reads a real file, other platforms always error).
	_, _ = CurrentBootID()
}
