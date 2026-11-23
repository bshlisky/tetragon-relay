package hostprobe

import (
	"encoding/json"
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

func TestLoad_Valid(t *testing.T) {
	dir := t.TempDir()
	p := writeFacts(t, dir, validFacts("boot-a"))

	c, ok := Load(p, "boot-a")
	if !ok {
		t.Fatal("Load reported failure for a valid, fresh facts file")
	}
	if !c.KprobeOverride() || !c.LSMBPF() || !c.UsrmergeOK() {
		t.Fatalf("capabilities not reported as available: %+v", c)
	}
	facts, ok := c.Facts()
	if !ok || facts.KernelRelease != "5.14.0-500.el9.x86_64" {
		t.Fatalf("Facts() = %+v, %v", facts, ok)
	}
}

func TestLoad_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		path string
		boot string
	}{
		{"missing_file", filepath.Join(dir, "does-not-exist.json"), "boot-a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := Load(tc.path, tc.boot)
			if ok {
				t.Fatal("Load reported success for a missing file")
			}
			assertFailClosed(t, c)
		})
	}

	t.Run("stale_boot_id", func(t *testing.T) {
		p := writeFacts(t, dir, validFacts("boot-old"))
		c, ok := Load(p, "boot-new")
		if ok {
			t.Fatal("Load reported success for a stale boot_id")
		}
		assertFailClosed(t, c)
	})

	t.Run("empty_current_boot_id", func(t *testing.T) {
		p := writeFacts(t, dir, validFacts("boot-a"))
		c, ok := Load(p, "")
		if ok {
			t.Fatal("Load reported success with an empty current boot_id")
		}
		assertFailClosed(t, c)
	})

	t.Run("wrong_schema_version", func(t *testing.T) {
		f := validFacts("boot-a")
		f.SchemaVersion = 999
		p := writeFacts(t, dir, f)
		c, ok := Load(p, "boot-a")
		if ok {
			t.Fatal("Load reported success for an unsupported schema version")
		}
		assertFailClosed(t, c)
	})

	t.Run("corrupt_json", func(t *testing.T) {
		p := filepath.Join(dir, "corrupt.json")
		if err := os.WriteFile(p, []byte("{not valid json"), 0o640); err != nil {
			t.Fatal(err)
		}
		c, ok := Load(p, "boot-a")
		if ok {
			t.Fatal("Load reported success for corrupt JSON")
		}
		assertFailClosed(t, c)
	})

	t.Run("duplicate_key_rejected", func(t *testing.T) {
		p := filepath.Join(dir, "dup.json")
		raw := `{"schema_version":1,"boot_id":"boot-a","boot_id":"boot-b"}`
		if err := os.WriteFile(p, []byte(raw), 0o640); err != nil {
			t.Fatal(err)
		}
		c, ok := Load(p, "boot-a")
		if ok {
			t.Fatal("Load reported success for a duplicate-key JSON document")
		}
		assertFailClosed(t, c)
	})

	t.Run("unknown_field_rejected", func(t *testing.T) {
		p := filepath.Join(dir, "unknown.json")
		raw := `{"schema_version":1,"boot_id":"boot-a","totally_unknown_field":true}`
		if err := os.WriteFile(p, []byte(raw), 0o640); err != nil {
			t.Fatal(err)
		}
		c, ok := Load(p, "boot-a")
		if ok {
			t.Fatal("Load reported success for a document with an unknown field")
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
