package telemetry

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/chainverify"
)

const testHost = "11111111-1111-1111-1111-111111111111"

type recAuditor struct {
	mu    sync.Mutex
	steps []string
}

func (a *recAuditor) Record(step, _ string, _ error) {
	a.mu.Lock()
	a.steps = append(a.steps, step)
	a.mu.Unlock()
}

func (a *recAuditor) count(step string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, s := range a.steps {
		if s == step {
			n++
		}
	}
	return n
}

type countingRand struct{ n byte }

func (r *countingRand) Read(p []byte) (int, error) {
	r.n++
	for i := range p {
		p[i] = r.n
	}
	return len(p), nil
}

var testKey = bytes.Repeat([]byte{7}, 48)

func spoolCfg(t *testing.T, dir string, fsys FS, boot string) SpoolConfig {
	t.Helper()
	return SpoolConfig{
		Dir: dir, FS: fsys, Key: testKey, MaxBytes: 1 << 30,
		HostUUID: testHost, BootID: boot, AgentVersion: "test",
		Epochs: func() map[string]uint64 { return map[string]uint64{"prod": 3} },
		Clock:  func() time.Time { return time.Unix(1000, 0) },
		Rand:   &countingRand{}, Auditor: &recAuditor{},
	}
}

func mustOpen(t *testing.T, cfg SpoolConfig) *Spool {
	t.Helper()
	s, err := OpenSpool(cfg)
	if err != nil {
		t.Fatalf("OpenSpool: %v", err)
	}
	return s
}

func rec(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte{byte(i + 1), 0xaa}
	}
	return out
}

// spooled reads every batch file in order and verifies the chain(s).
func spooled(t *testing.T, s *Spool) []chainverify.Input {
	t.Helper()
	var in []chainverify.Input
	var cur *Entry
	for {
		e, ok := s.After(cur)
		if !ok {
			return in
		}
		c := e
		cur = &c
		h, p, err := s.Read(e)
		if err != nil {
			t.Fatalf("Read %v: %v", e, err)
		}
		in = append(in, chainverify.Input{Header: h, Payload: p})
	}
}

func TestSpool_NewChainContinueAndBootChange(t *testing.T) {
	dir := t.TempDir()
	cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
	s := mustOpen(t, cfg)
	if _, err := s.AppendEvents(batch.ClassSecurity, rec(2), 5, 9); err != nil {
		t.Fatal(err)
	}
	first := s.Chain()
	if st := s.Stats(); st.LastSeq != 2 || st.Backlog != 2 {
		t.Fatalf("stats = %+v", st)
	}
	// Restart in the same boot: the chain continues.
	s2 := mustOpen(t, cfg)
	if s2.Chain() != first || s2.Stats().LastSeq != 2 {
		t.Fatalf("restart did not continue the chain: %s seq %d", s2.Chain(), s2.Stats().LastSeq)
	}
	if _, err := s2.AppendEvents(batch.ClassNonSecurity, rec(1), 10, 10); err != nil {
		t.Fatal(err)
	}
	r := chainverify.Verify(testHost, spooled(t, s2))
	if !r.Clean() || len(r.Chains) != 1 || r.Chains[0].Contiguous != 3 {
		t.Fatalf("report = %+v", r)
	}
	// Reboot: a new chain whose reset names the old head.
	cfg.BootID = "boot-b"
	s3 := mustOpen(t, cfg)
	if s3.Chain() == first || s3.Stats().LastSeq != 1 {
		t.Fatal("boot change did not start a new chain")
	}
	r = chainverify.Verify(testHost, spooled(t, s3))
	if !r.Clean() || len(r.Chains) != 2 || r.Chains[1].ResetReason != batch.ReasonBootChanged {
		t.Fatalf("report = %+v", r)
	}
	// Old chain is first in send order.
	e, _ := s3.After(nil)
	if e.Chain != first {
		t.Fatal("old chain is not drained first")
	}
}

func TestSpool_ResetReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mut    func(dir string, cfg *SpoolConfig)
		reason string
	}{
		{"head missing", func(dir string, _ *SpoolConfig) { _ = os.Remove(filepath.Join(dir, headName)) }, batch.ReasonHeadMissing},
		{"head hmac", func(dir string, _ *SpoolConfig) {
			p := filepath.Join(dir, headName)
			b, _ := os.ReadFile(p)
			b[5] ^= 1
			_ = os.WriteFile(p, b, 0o600)
		}, batch.ReasonHeadCorrupt},
		{"head garbage", func(dir string, _ *SpoolConfig) { _ = os.WriteFile(filepath.Join(dir, headName), []byte("x"), 0o600) }, batch.ReasonHeadCorrupt},
		{"other key", func(_ string, c *SpoolConfig) { c.Key = bytes.Repeat([]byte{8}, 48) }, batch.ReasonHeadCorrupt},
		{"other host", func(_ string, c *SpoolConfig) { c.HostUUID = "22222222-2222-2222-2222-222222222222" }, batch.ReasonHeadCorrupt},
		{"tampered mode", func(_ string, c *SpoolConfig) { c.Tampered = true }, batch.ReasonTamperedMode},
		{"no boot id", func(_ string, c *SpoolConfig) { c.BootID = "" }, batch.ReasonBootIDUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
			s := mustOpen(t, cfg)
			if _, err := s.AppendEvents(batch.ClassSecurity, rec(1), 1, 1); err != nil {
				t.Fatal(err)
			}
			old := s.Chain()
			tc.mut(dir, &cfg)
			s2 := mustOpen(t, cfg)
			if s2.Chain() == old {
				t.Fatal("chain continued")
			}
			var resetReason string
			var cur *Entry
			for {
				e, ok := s2.After(cur)
				if !ok {
					break
				}
				c := e
				cur = &c
				if e.Chain == s2.Chain() && e.Seq == 1 {
					_, p, err := s2.Read(e)
					if err != nil {
						t.Fatal(err)
					}
					r, _ := batch.ParseReset(p)
					resetReason = r.Reason
				}
			}
			if resetReason != tc.reason {
				t.Fatalf("reset reason = %q, want %q", resetReason, tc.reason)
			}
		})
	}
}

func TestSpool_CorruptFileDroppedNeverSent(t *testing.T) {
	dir := t.TempDir()
	cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
	aud := cfg.Auditor.(*recAuditor)
	s := mustOpen(t, cfg)
	e, _ := s.AppendEvents(batch.ClassSecurity, rec(1), 1, 1)
	p := filepath.Join(dir, e.name)
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 1
	_ = os.WriteFile(p, b, 0o600)
	// On read by a running spool.
	if _, _, err := s.Read(e); !errors.Is(err, ErrSpoolCorrupt) {
		t.Fatalf("Read: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) || s.Stats().CorruptDropped != 1 || aud.count("telemetry_batch_corrupt") != 1 {
		t.Fatal("corrupt file not deleted, counted and audited")
	}
	// On open.
	e2, _ := s.AppendEvents(batch.ClassSecurity, rec(1), 1, 1)
	_ = os.WriteFile(filepath.Join(dir, e2.name), []byte("TRS1junk"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "stale.tmp"), []byte("x"), 0o600)
	// A file renamed to another seq fails its MAC (the name is MACed).
	s2 := mustOpen(t, cfg)
	if s2.Stats().CorruptDropped != 1 {
		t.Fatalf("stats = %+v", s2.Stats())
	}
	if _, err := os.Stat(filepath.Join(dir, "stale.tmp")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("temp file not removed")
	}
}

func TestSpool_RenamedFileFailsMAC(t *testing.T) {
	dir := t.TempDir()
	cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
	s := mustOpen(t, cfg)
	e, _ := s.AppendEvents(batch.ClassSecurity, rec(1), 1, 1)
	renamed := strings.Replace(e.name, "0000000001-", "0000000002-", 1)
	if err := os.Rename(filepath.Join(dir, e.name), filepath.Join(dir, renamed)); err != nil {
		t.Fatal(err)
	}
	s2 := mustOpen(t, cfg)
	if s2.Stats().CorruptDropped != 1 {
		t.Fatalf("renamed file accepted: %+v", s2.Stats())
	}
}

func TestSpool_AckDeletesOnlyThatChainUpToSeq(t *testing.T) {
	dir := t.TempDir()
	cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
	s := mustOpen(t, cfg)
	for i := 0; i < 3; i++ {
		_, _ = s.AppendEvents(batch.ClassSecurity, rec(1), 1, 1)
	}
	if n := s.Ack(batch.ChainID{0xff}, 10); n != 0 {
		t.Fatal("ack for another chain deleted files")
	}
	if n := s.Ack(s.Chain(), 2); n != 2 || s.Stats().Backlog != 2 {
		t.Fatalf("Ack deleted %d, backlog %d", n, s.Stats().Backlog)
	}
	e, _ := s.After(nil)
	if e.Seq != 3 {
		t.Fatalf("oldest left = %d", e.Seq)
	}
}

func TestSpool_OverflowDropsNonSecurityFirstAndDeclares(t *testing.T) {
	dir := t.TempDir()
	cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
	s := mustOpen(t, cfg)
	big := [][]byte{bytes.Repeat([]byte{1}, 2000)}
	for i := 0; i < 3; i++ {
		_, _ = s.AppendEvents(batch.ClassNonSecurity, big, 1, 1)
		_, _ = s.AppendEvents(batch.ClassSecurity, big, 1, 1)
	}
	// Cap the spool so the next batch forces drops.
	s.cfg.MaxBytes = s.Stats().Bytes + 3000
	if _, err := s.AppendEvents(batch.ClassSecurity, big, 1, 1); err != nil {
		t.Fatal(err)
	}
	var classes []string
	var cur *Entry
	for {
		e, ok := s.After(cur)
		if !ok {
			break
		}
		c := e
		cur = &c
		classes = append(classes, e.Class)
	}
	nonSec := strings.Count(strings.Join(classes, ","), batch.ClassNonSecurity)
	sec := strings.Count(strings.Join(classes, ","), batch.ClassSecurity) - nonSec
	if sec != 4 || nonSec >= 3 {
		t.Fatalf("classes after overflow = %v", classes)
	}
	r := chainverify.Verify(testHost, spooled(t, s))
	dropped := false
	for _, f := range r.Findings {
		if f.Kind == chainverify.Dropped && strings.Contains(f.Detail, "non_security") {
			dropped = true
		}
	}
	if !dropped || !r.Clean() {
		t.Fatalf("dropped record missing or chain not clean: %+v", r.Findings)
	}
	if s.Stats().OverflowDropped == 0 {
		t.Fatal("overflow not counted")
	}
	// Then security, once no non_security batch is left.
	s.cfg.MaxBytes = s.Stats().Bytes + 1000
	if _, err := s.AppendEvents(batch.ClassSecurity, big, 1, 1); err != nil {
		t.Fatal(err)
	}
	r = chainverify.Verify(testHost, spooled(t, s))
	if !r.Clean() {
		t.Fatalf("findings = %+v", r.Findings)
	}
	found := false
	for _, f := range r.Findings {
		if f.Kind == chainverify.Dropped && strings.Contains(f.Detail, "class=security") {
			found = true
		}
	}
	if !found {
		t.Fatal("no security dropped record once non_security was exhausted")
	}
	// Only control batches left and still no room: refused.
	s.Ack(s.Chain(), s.Stats().LastSeq)
	s.cfg.MaxBytes = 10
	if _, err := s.AppendEvents(batch.ClassSecurity, big, 1, 1); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("only control batches left: err = %v, want ErrSpoolFull", err)
	}
}

func TestSpool_FullOfControlRefuses(t *testing.T) {
	dir := t.TempDir()
	cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
	cfg.MaxBytes = 10
	s := mustOpen(t, cfg) // the chain_reset alone exceeds the cap
	if _, err := s.AppendEvents(batch.ClassSecurity, rec(1), 1, 1); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.AppendEvents("control", rec(1), 1, 1); err == nil {
		t.Fatal("control class accepted for events")
	}
}

func TestSpool_ConfigValidation(t *testing.T) {
	base := spoolCfg(t, t.TempDir(), OSFS{}, "b")
	for name, mut := range map[string]func(*SpoolConfig){
		"dir":   func(c *SpoolConfig) { c.Dir = "" },
		"key":   func(c *SpoolConfig) { c.Key = nil },
		"max":   func(c *SpoolConfig) { c.MaxBytes = 0 },
		"host":  func(c *SpoolConfig) { c.HostUUID = "" },
		"clock": func(c *SpoolConfig) { c.Clock = nil },
	} {
		c := base
		mut(&c)
		if _, err := OpenSpool(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c := base
	c.Dir = filepath.Join(c.Dir, "missing")
	if _, err := OpenSpool(c); err == nil {
		t.Error("missing dir accepted")
	}
	if _, err := DeriveSpoolKey([]byte("short")); err == nil {
		t.Error("short store key accepted")
	}
	k1, _ := DeriveSpoolKey(bytes.Repeat([]byte{1}, 32))
	k2, _ := DeriveSpoolKey(bytes.Repeat([]byte{1}, 32))
	if len(k1) != 48 || !bytes.Equal(k1, k2) || bytes.Equal(k1, bytes.Repeat([]byte{1}, 32)[:32]) {
		t.Error("DeriveSpoolKey is not a deterministic 48-byte derived key")
	}
}
