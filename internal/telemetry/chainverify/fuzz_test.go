package chainverify

import (
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	bt "github.com/bshlisky/tetragon-relay/internal/telemetry/batch/batchtest"
)

// FuzzChainVerify: the verifier never panics on any reordering, drop,
// duplication or corruption of a valid chain, and a report it calls clean
// really has no hole: every chain is contiguous to its highest seq.
func FuzzChainVerify(f *testing.F) {
	c := bt.NewChain(1, "boot")
	chain := []bt.Built{c.Reset(batch.ReasonHeadMissing, nil)}
	for i := 0; i < 7; i++ {
		chain = append(chain, c.Events(batch.ClassSecurity, i+1))
	}
	chain = append(chain, c.Dropped(batch.ClassNonSecurity, c.Ref(chain[2])))
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{0, 2, 1, 1, 200, 3})
	f.Fuzz(func(t *testing.T, ops []byte) {
		var in []Input
		for i, op := range ops {
			if i > 64 {
				break
			}
			b := chain[int(op)%len(chain)]
			h, p := append([]byte(nil), b.Header...), append([]byte(nil), b.Payload...)
			if op >= 128 && len(h) > 0 {
				h[int(op)%len(h)] ^= 1 // corrupt the header
			} else if op >= 64 && len(p) > 0 {
				p[int(op)%len(p)] ^= 1 // corrupt the payload
			}
			in = append(in, Input{Header: h, Payload: p})
		}
		r := Verify("", in)
		if r.Clean() {
			for _, s := range r.Chains {
				if s.Contiguous != s.MaxSeq {
					t.Fatalf("clean report with a hole: %+v", s)
				}
			}
		}
	})
}
