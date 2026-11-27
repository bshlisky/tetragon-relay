package chainverify

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
	bt "github.com/bshlisky/tetragon-relay/internal/telemetry/batch/batchtest"
)

func in(bs ...bt.Built) []Input {
	out := make([]Input, len(bs))
	for i, b := range bs {
		out[i] = Input{Header: b.Header, Payload: b.Payload}
	}
	return out
}

func kinds(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, string(f.Kind))
	}
	return strings.Join(s, ",")
}

// validChain returns seq 1..n of a fresh chain (reset, then events).
func validChain(id byte, boot string, n int) (*bt.Chain, []bt.Built) {
	c := bt.NewChain(id, boot)
	out := []bt.Built{c.Reset(batch.ReasonHeadMissing, nil)}
	for i := 1; i < n; i++ {
		class := batch.ClassSecurity
		if i%2 == 0 {
			class = batch.ClassNonSecurity
		}
		out = append(out, c.Events(class, i))
	}
	return c, out
}

func TestVerify_Table(t *testing.T) {
	c, ok5 := validChain(1, "boot-a", 5)
	// A second chain after a reboot, naming the first chain's head.
	c2 := bt.NewChain(2, "boot-b")
	ref := c.Ref(ok5[4])
	reboot := []bt.Built{c2.Reset(batch.ReasonBootChanged, &ref), c2.Events(batch.ClassSecurity, 1)}

	// A fork: a different batch 3 built on the real batch 2.
	_, fb := validChain(1, "boot-a", 3)
	// Build seq 3 that links to fb[1] but differs from fb[2].
	alt := bt.NewChain(1, "boot-a")
	alt.Reset(batch.ReasonHeadMissing, nil)
	alt.Events(batch.ClassSecurity, 1)
	alt3 := alt.Events(batch.ClassSecurity, 7)

	// A batch whose prev_hash names the wrong predecessor.
	wrong := bt.NewChain(1, "boot-a")
	wrong.Reset(batch.ReasonHeadCorrupt, nil) // different reset payload -> different hash
	wrong.Events(batch.ClassSecurity, 1)
	wrong3 := wrong.Events(batch.ClassSecurity, 2)

	// Drops: batches 2 and 4 dropped, declared by a dropped record at 6.
	dc, d := validChain(3, "boot-a", 5)
	drop := dc.Dropped(batch.ClassNonSecurity, dc.Ref(d[1]), dc.Ref(d[3]))
	// A dropped record whose hash for seq 2 lies.
	dc2, d2 := validChain(4, "boot-a", 3)
	lying := dc2.Dropped(batch.ClassNonSecurity, batch.Ref{ChainID: dc.ID, Seq: 2, Hash: batch.Hash{0xee}})

	badPayloadDigest := bt.Built{Header: ok5[1].Header, Payload: append([]byte{}, ok5[2].Payload...)}

	cases := []struct {
		name  string
		input []bt.Built
		want  string // comma-joined finding kinds, in order
		clean bool
	}{
		{"valid chain", ok5, "chain_reset", true},
		{"gap", []bt.Built{ok5[0], ok5[1], ok5[3], ok5[4]}, "chain_reset,chain_gap", false},
		{"gap at the start", ok5[1:], "chain_gap", false},
		{"reorder", []bt.Built{ok5[0], ok5[2], ok5[1], ok5[3]}, "chain_reset,chain_reorder", false},
		{"identical duplicate after reconnect", []bt.Built{ok5[0], ok5[1], ok5[2], ok5[1], ok5[2], ok5[3]}, "chain_reset,duplicate,duplicate", true},
		{"duplicate with a different hash", []bt.Built{fb[0], fb[1], fb[2], alt3}, "chain_reset,duplicate_mismatch,chain_fork", false},
		{"fork: prev_hash names another predecessor", []bt.Built{fb[0], fb[1], wrong3}, "chain_reset,chain_fork", false},
		{"fork detected when the predecessor arrives later", []bt.Built{fb[0], wrong3, fb[1]}, "chain_reset,chain_reorder,chain_fork", false},
		{"reset and boot change", append(append([]bt.Built{}, ok5...), reboot...), "chain_reset,chain_reset", true},
		{"boot change naming a wrong head", append(append([]bt.Built{}, ok5[:5]...), func() []bt.Built {
			x := bt.NewChain(2, "boot-b")
			r := batch.Ref{ChainID: c.ID, Seq: 5, Hash: batch.Hash{1}}
			return []bt.Built{x.Reset(batch.ReasonBootChanged, &r)}
		}()...), "chain_reset,chain_fork,chain_reset", false},
		{"same chain id, different boot", []bt.Built{ok5[0], func() bt.Built {
			x := bt.NewChain(1, "boot-z")
			x.Reset(batch.ReasonHeadMissing, nil)
			return x.Events(batch.ClassSecurity, 1)
		}()}, "chain_reset,chain_fork,chain_fork", false},
		{"declared drops close the gaps", []bt.Built{d[0], d[2], d[4], drop}, "chain_reset,dropped", true},
		{"dropped record lying about a hash", []bt.Built{d[0], d[1], d2[0], d2[1], d2[2], lying}, "chain_reset,chain_reset,dropped,chain_fork", false},
		{"bad header", []bt.Built{{Header: []byte(`{"v":1}`), Payload: nil}}, "bad_header", false},
		{"hash mismatch", []bt.Built{ok5[0], badPayloadDigest}, "chain_reset,hash_mismatch", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Verify(bt.Host, in(tc.input...))
			if got := kinds(r.Findings); got != tc.want {
				t.Fatalf("findings = %s, want %s\n%+v", got, tc.want, r.Findings)
			}
			if r.Clean() != tc.clean {
				t.Fatalf("Clean() = %v, want %v", r.Clean(), tc.clean)
			}
		})
	}
}

func TestVerify_DeclaredDropsLeaveNoGapAndLinkAcross(t *testing.T) {
	dc, d := validChain(3, "boot-a", 5)
	drop := dc.Dropped(batch.ClassNonSecurity, dc.Ref(d[1]), dc.Ref(d[3]))
	r := Verify(bt.Host, in(d[0], d[2], d[4], drop))
	for _, f := range r.Findings {
		if f.Kind == ChainGap || f.Kind == ChainFork {
			t.Fatalf("unexpected %v", f)
		}
	}
	s := r.Chains[0]
	if s.Contiguous != 6 || s.MaxSeq != 6 || s.Received != 4 || s.Declared != 2 || s.ResetReason != batch.ReasonHeadMissing {
		t.Fatalf("summary = %+v", s)
	}
	// The verifier checked seq 3's prev_hash against the declared hash of
	// seq 2: lying about it is a fork (TestVerify_Table), telling the
	// truth is not.
}

func TestVerify_DropFromAnOlderChain(t *testing.T) {
	old, ob := validChain(1, "boot-a", 3)
	cur := bt.NewChain(2, "boot-b")
	ref := old.Ref(ob[2])
	r0 := cur.Reset(batch.ReasonBootChanged, &ref)
	// The old chain's seq 2 was dropped from the spool before it was sent.
	drop := cur.Dropped(batch.ClassSecurity, old.Ref(ob[1]))
	r := Verify(bt.Host, in(ob[0], ob[2], r0, drop))
	if got := kinds(r.Findings); got != "chain_reset,chain_reset,dropped" {
		t.Fatalf("findings = %s", got)
	}
}

func TestVerify_HostMismatchAndFirstHost(t *testing.T) {
	_, b := validChain(1, "boot-a", 2)
	if got := kinds(Verify("other-host", in(b...)).Findings); got != "bad_header,bad_header" {
		t.Fatalf("findings = %s", got)
	}
	if r := Verify("", in(b...)); !r.Clean() || r.Chains[0].HostUUID != bt.Host {
		t.Fatalf("first host not adopted: %+v", r)
	}
}

func TestVerify_BadPayloads(t *testing.T) {
	c := bt.NewChain(5, "boot-a")
	reset := c.Reset(batch.ReasonHeadMissing, nil)
	// An events header whose count disagrees with its records.
	ev := c.Events(batch.ClassSecurity, 2)
	h, _ := batch.ParseHeader(ev.Header)
	h.Count = 3
	raw, _ := h.Marshal()
	bad := bt.Built{Header: raw, Payload: ev.Payload}
	r := Verify(bt.Host, in(reset, bad))
	if got := kinds(r.Findings); got != "chain_reset,bad_payload" {
		t.Fatalf("findings = %s", got)
	}
	// A control batch whose payload is not its kind's JSON.
	mk := func(kind string, seq uint64, payload []byte) bt.Built {
		hh := batch.Header{HostUUID: bt.Host, BootID: "b", ChainID: batch.ChainID{6}, Seq: seq, Kind: kind, Class: batch.ClassControl, AgentVersion: "t", Epochs: map[string]uint64{}, PayloadSHA256: sha256Of(payload)}
		if seq > 1 {
			hh.PrevHash = batch.Hash{1}
		}
		x, err := hh.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return bt.Built{Header: x, Payload: payload}
	}
	r = Verify(bt.Host, in(mk(batch.KindChainReset, 1, []byte("x")), mk(batch.KindDropped, 2, []byte("y"))))
	if got := kinds(r.Findings); got != "bad_payload,bad_payload,chain_fork" {
		t.Fatalf("findings = %s", got)
	}
}

func TestVerifier_IncrementalGapsAreNonDestructive(t *testing.T) {
	_, b := validChain(1, "boot-a", 4)
	v := New(bt.Host)
	v.Add(b[0].Header, b[0].Payload)
	v.Add(b[2].Header, b[2].Payload)
	if g := v.Gaps(); len(g) != 1 || g[0].Seq != 2 || g[0].LastSeq != 2 || g[0].Index != -1 {
		t.Fatalf("gaps = %+v", g)
	}
	v.Add(b[1].Header, b[1].Payload)
	if g := v.Gaps(); len(g) != 0 {
		t.Fatalf("gap not closed: %+v", g)
	}
	if fs := v.Add(b[3].Header, b[3].Payload); len(fs) != 0 {
		t.Fatalf("findings for a valid next batch: %+v", fs)
	}
}

func TestVerifier_EntryBound(t *testing.T) {
	_, b := validChain(1, "boot-a", 2)
	v := New(bt.Host)
	v.entries = MaxEntries
	if fs := v.Add(b[0].Header, b[0].Payload); kinds(fs) != "bad_payload" {
		t.Fatalf("findings = %s", kinds(fs))
	}
}

func sha256Of(b []byte) batch.Hash { return batch.Hash(sha256.Sum256(b)) }
