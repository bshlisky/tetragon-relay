package telemetry

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	"github.com/bshlisky/tetragon-relay/internal/telemetry/chainverify"
)

// seal is sealParts joined (the bytes appendLocked writes).
func (s *Spool) seal(name string, header, payload []byte) []byte {
	p := s.sealParts(name, header, payload, batch.HashOf(header, payload))
	return bytes.Join(p[:], nil)
}

// sealV1 is step 7a's batch file format (TRS1: HMAC over the name and
// the whole body), which a spool written by a 7a relayd still holds.
func (s *Spool) sealV1(name string, header, payload []byte) []byte {
	body := []byte(fileMagicV1)
	body = binary.BigEndian.AppendUint32(body, uint32(len(header))) //nolint:gosec // G115: test sizes
	body = append(body, header...)
	body = append(body, payload...)
	return append(body, s.mac([]byte(name), body)...)
}

// A 7a relayd's spooled batches survive the upgrade: rewritten in the 7a
// format, they are accepted at Open, read back byte for byte, verify as one
// chain together with batches the new code appends, and a v1 file with one
// flipped bit is still rejected.
func TestSpool_ReadsStep7aFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := spoolCfg(t, dir, OSFS{}, "boot-a")
	s := mustOpen(t, cfg)
	for i := 0; i < 3; i++ {
		if _, err := s.AppendEvents(batch.ClassSecurity, rec(2), 5, 9); err != nil {
			t.Fatal(err)
		}
	}
	want := spooled(t, s)
	// Rewrite every batch file in the 7a format.
	des, _ := os.ReadDir(dir)
	var victim string
	for _, de := range des {
		if filepath.Ext(de.Name()) != fileSuffix {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(dir, de.Name()))
		b, err := s.unseal(de.Name(), raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, de.Name()), s.sealV1(de.Name(), b.RawHeader, b.Payload), 0o600); err != nil {
			t.Fatal(err)
		}
		victim = de.Name()
	}
	s2 := mustOpen(t, cfg)
	got := spooled(t, s2)
	if len(got) != len(want) {
		t.Fatalf("after the upgrade %d batches, want %d", len(got), len(want))
	}
	for i := range got {
		if !bytes.Equal(got[i].Header, want[i].Header) || !bytes.Equal(got[i].Payload, want[i].Payload) {
			t.Fatalf("batch %d changed across the format upgrade", i)
		}
	}
	if _, err := s2.AppendEvents(batch.ClassNonSecurity, rec(1), 10, 10); err != nil {
		t.Fatal(err)
	}
	if r := chainverify.Verify(testHost, spooled(t, s2)); !r.Clean() || r.Chains[0].Contiguous != 5 {
		t.Fatalf("mixed-format chain: %+v", r)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, victim))
	raw[len(fileMagicV1)+6] ^= 0x01
	if _, err := s2.unseal(victim, raw); err == nil {
		t.Fatal("a modified TRS1 file was accepted")
	}
	if _, err := s2.unseal(victim, append([]byte("TRS9"), raw[4:]...)); err == nil {
		t.Fatal("an unknown magic was accepted")
	}
}

// The payload buffer is not retained: the caller may overwrite it.
func TestSpool_PayloadNotRetainedAndCountChecked(t *testing.T) {
	s := mustOpen(t, spoolCfg(t, t.TempDir(), OSFS{}, "boot-a"))
	payload := batch.AppendRecord(batch.AppendRecord(nil, []byte("one")), []byte("two"))
	e, err := s.AppendEventsPayload(batch.ClassSecurity, payload, 2, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := range payload {
		payload[i] = 0xff
	}
	if _, p, err := s.Read(e); err != nil || !bytes.Contains(p, []byte("two")) {
		t.Fatalf("Read after overwriting the caller's buffer: %v", err)
	}
	for _, c := range []struct {
		payload []byte
		count   uint64
	}{
		{batch.AppendRecord(nil, []byte("x")), 2},
		{batch.AppendRecord(nil, []byte("x")), 0},
		{[]byte{0, 0, 0}, 1},
		{[]byte{0, 0, 0, 9, 1}, 1},
		{[]byte{0, 0, 0, 0}, 1},
		{nil, 0},
	} {
		if _, err := s.AppendEventsPayload(batch.ClassSecurity, c.payload, c.count, 1, 1); err == nil {
			t.Errorf("payload %x with count %d accepted", c.payload, c.count)
		}
	}
}
