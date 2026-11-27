package telemetry

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
)

// FuzzSpoolFile: the batch-file reader never panics on any file, accepts a
// file only if its HMAC verifies, and, when the HMAC is valid (a file the
// agent itself sealed around arbitrary bytes), accepts it only if the
// header and payload inside are a valid batch whose name matches.
func FuzzSpoolFile(f *testing.F) {
	s := &Spool{cfg: SpoolConfig{Key: testKey}}
	h := batch.Header{HostUUID: testHost, BootID: "b", ChainID: batch.ChainID{1}, Seq: 2, PrevHash: batch.Hash{1},
		Kind: batch.KindEvents, Class: batch.ClassSecurity, Count: 1, AgentVersion: "t", Epochs: map[string]uint64{}}
	p := batch.AppendRecord(nil, []byte("e"))
	h.PayloadSHA256 = sha256.Sum256(p)
	raw, _ := h.Marshal()
	name := fileName(1, h.ChainID, 2)
	f.Add(s.seal(name, raw, p), uint32(len(raw)), name)
	f.Add(s.sealV1(name, raw, p), uint32(len(raw))|1<<31, name)
	f.Add([]byte("TRS1"), uint32(0), "x.batch")
	f.Add([]byte("TRS2"), uint32(0), "x.batch")
	f.Fuzz(func(t *testing.T, body []byte, split uint32, name string) {
		_, _ = s.unseal(name, body) // arbitrary bytes: must not panic
		// Sealed by the agent around arbitrary bytes.
		// The high bit of split picks the format: step 7a's (TRS1) or 7b's.
		cut := int(split&^(1<<31)) % (len(body) + 1)
		sealed := s.seal(name, body[:cut], body[cut:])
		if split&(1<<31) != 0 {
			sealed = s.sealV1(name, body[:cut], body[cut:])
		}
		b, err := s.unseal(name, sealed)
		if err != nil {
			return
		}
		if _, perr := batch.Parse(body[:cut], body[cut:]); perr != nil {
			t.Fatalf("accepted an invalid batch: %v", perr)
		}
		gen, chain, seq, ok := parseFileName(name)
		if !ok || gen == 0 || chain != b.Header.ChainID || seq != b.Header.Seq {
			t.Fatalf("accepted a file whose name does not match its header: %q", name)
		}
		// Flipping any byte breaks it.
		i := int(binary.BigEndian.Uint32(append(sealed[:0:0], 0, 0, 0, byte(split)))) % len(sealed)
		sealed[i] ^= 0x80
		if _, err := s.unseal(name, sealed); err == nil {
			t.Fatal("accepted a modified file")
		}
	})
}
