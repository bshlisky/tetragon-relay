package batch

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// FuzzBatchHeader: ParseHeader (and the payload parsers) never panic, and
// anything ParseHeader accepts re-marshals to the identical bytes.
func FuzzBatchHeader(f *testing.F) {
	h := sampleHeader()
	raw, _ := h.Marshal()
	f.Add(raw)
	r, _ := (&Reset{Reason: ReasonBootChanged, Prev: &Ref{Seq: 3}}).Marshal()
	f.Add(r)
	d, _ := (&Dropped{Class: ClassSecurity, Batches: []Ref{{Seq: 1}}}).Marshal()
	f.Add(d)
	f.Add([]byte(`{"v":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if got, err := ParseHeader(b); err == nil {
			again, merr := got.Marshal()
			if merr != nil || !bytes.Equal(again, b) {
				t.Fatalf("accepted a header that does not round-trip: %q", b)
			}
			_ = HashOf(b, nil)
		}
		if got, err := ParseDropped(b); err == nil {
			again, _ := got.Marshal()
			if !bytes.Equal(again, b) {
				t.Fatalf("dropped payload not canonical: %q", b)
			}
		}
		if got, err := ParseReset(b); err == nil {
			again, _ := got.Marshal()
			if !bytes.Equal(again, b) {
				t.Fatalf("reset payload not canonical: %q", b)
			}
		}
		_, _ = SplitRecords(b, uint64(len(b)%7)+1)
		_, _ = Parse(b, b)
		_, _ = Parse(raw, b)
		hh := sampleHeader()
		hh.PayloadSHA256 = sha256.Sum256(b)
		if hr, err := hh.Marshal(); err == nil {
			if _, err := Parse(hr, b); err != nil && len(b) <= 1<<20 {
				t.Fatalf("valid header with matching digest rejected: %v", err)
			}
		}
	})
}
