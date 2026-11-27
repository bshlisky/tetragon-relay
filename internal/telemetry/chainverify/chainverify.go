// Package chainverify is the reference telemetry chain verifier
// (docs/telemetry-contract.md section 4; ADR 0039). It is deterministic
// and has no I/O, clock or global state, so the backend team can call it
// or port it line by line.
//
// Use Verify for a complete, ordered list of received batches, or a
// Verifier to feed batches one at a time as a collector receives them
// (Add) and ask for the unresolved gaps whenever needed (Gaps).
//
// What it flags:
//   - bad_header, hash_mismatch, bad_payload: the batch is malformed;
//     bad_header and hash_mismatch batches are not part of any chain.
//   - chain_reset: every seq-1 batch, with its reason.
//   - dropped: every dropped record (declared loss).
//   - duplicate: the same (chain, seq, hash) again (expected after a
//     reconnect; informational).
//   - duplicate_mismatch and chain_fork: the same (chain, seq) with a
//     different hash, or a prev_hash that does not match the hash of the
//     batch before it (received, or declared by a dropped record).
//   - chain_reorder: a never-seen seq arriving below the highest seq
//     already seen in its chain. A correct agent sends each chain in
//     order, so this only happens if something reordered the stream.
//   - chain_gap: seqs neither received nor declared dropped, below the
//     highest seq known in the chain (reported by Gaps, not by Add).
package chainverify

import (
	"errors"
	"fmt"
	"sort"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
)

// Kind names a finding.
type Kind string

// Finding kinds (docs/telemetry-contract.md section 4).
const (
	BadHeader         Kind = "bad_header"
	HashMismatch      Kind = "hash_mismatch"
	BadPayload        Kind = "bad_payload"
	ChainReset        Kind = "chain_reset"
	Dropped           Kind = "dropped"
	Duplicate         Kind = "duplicate"
	DuplicateMismatch Kind = "duplicate_mismatch"
	ChainFork         Kind = "chain_fork"
	ChainReorder      Kind = "chain_reorder"
	ChainGap          Kind = "chain_gap"
)

// MaxEntries bounds how many (chain, seq) entries one Verifier tracks.
// Past it, Add reports BadPayload and ignores the batch.
const MaxEntries = 1 << 20

// Finding is one verdict.
type Finding struct {
	Kind Kind
	// Index is the batch's position in Add's call order (0-based), or -1
	// for a finding from Gaps.
	Index   int
	ChainID string
	Seq     uint64
	// LastSeq is the end of the range for chain_gap (Seq..LastSeq);
	// otherwise equal to Seq.
	LastSeq uint64
	Detail  string
}

// ChainSummary describes one chain as verified so far.
type ChainSummary struct {
	ChainID  string
	HostUUID string
	BootID   string
	// Contiguous is the highest seq such that every seq 1..Contiguous is
	// received or declared dropped.
	Contiguous uint64
	// MaxSeq is the highest seq received or declared.
	MaxSeq   uint64
	Received int
	Declared int
	// ResetReason is the seq-1 chain_reset's reason, if received.
	ResetReason string
}

// Input is one batch exactly as received.
type Input struct {
	Header  []byte
	Payload []byte
}

// Report is Verify's result.
type Report struct {
	Findings []Finding
	Chains   []ChainSummary
}

// Clean reports whether the report has no finding other than the
// expected ones (chain_reset with reason boot_changed for every chain
// after the first, informational duplicates, and declared drops).
func (r Report) Clean() bool {
	for _, f := range r.Findings {
		switch f.Kind {
		case Duplicate, Dropped, ChainReset:
		case BadHeader, HashMismatch, BadPayload, DuplicateMismatch, ChainFork, ChainReorder, ChainGap:
			return false
		default:
			return false
		}
	}
	return true
}

type entry struct {
	hash     batch.Hash
	prev     batch.Hash
	received bool
	declared bool
}

type chain struct {
	id          batch.ChainID
	identified  bool // host and boot known (a batch of the chain was received)
	host, boot  string
	entries     map[uint64]*entry
	maxSeq      uint64
	contiguous  uint64
	received    int
	declared    int
	resetReason string
}

// Verifier is the incremental form. The zero value is not usable; use
// New.
type Verifier struct {
	host    string
	chains  map[batch.ChainID]*chain
	order   []batch.ChainID
	n       int
	entries int
}

// New returns a Verifier. expectedHost is the host UUID from the
// client certificate; every batch must carry it. "" accepts the first
// batch's host and then requires it.
func New(expectedHost string) *Verifier {
	return &Verifier{host: expectedHost, chains: map[batch.ChainID]*chain{}}
}

// Verify runs a fresh Verifier over inputs in order and returns every
// finding, including the gaps left at the end.
func Verify(expectedHost string, inputs []Input) Report {
	v := New(expectedHost)
	var r Report
	for _, in := range inputs {
		r.Findings = append(r.Findings, v.Add(in.Header, in.Payload)...)
	}
	r.Findings = append(r.Findings, v.Gaps()...)
	r.Chains = v.Chains()
	return r
}

func (v *Verifier) chain(id batch.ChainID) *chain {
	c, ok := v.chains[id]
	if !ok {
		c = &chain{id: id, entries: map[uint64]*entry{}}
		v.chains[id] = c
		v.order = append(v.order, id)
	}
	return c
}

// Add verifies one batch and returns its findings.
func (v *Verifier) Add(header, payload []byte) []Finding {
	idx := v.n
	v.n++
	f := func(k Kind, chainID string, seq uint64, format string, a ...any) Finding {
		return Finding{Kind: k, Index: idx, ChainID: chainID, Seq: seq, LastSeq: seq, Detail: fmt.Sprintf(format, a...)}
	}
	b, err := batch.Parse(header, payload)
	if err != nil {
		if errors.Is(err, batch.ErrPayloadDigest) {
			h, _ := batch.ParseHeader(header)
			return []Finding{f(HashMismatch, h.ChainID.String(), h.Seq, "%v", err)}
		}
		return []Finding{f(BadHeader, "", 0, "%v", err)}
	}
	h := b.Header
	cid := h.ChainID.String()
	if v.host == "" {
		v.host = h.HostUUID
	}
	if h.HostUUID != v.host {
		return []Finding{f(BadHeader, cid, h.Seq, "host_uuid %q, want %q", h.HostUUID, v.host)}
	}
	if v.entries >= MaxEntries {
		return []Finding{f(BadPayload, cid, h.Seq, "verifier tracks %d entries already; batch ignored", MaxEntries)}
	}

	var out []Finding
	c := v.chain(h.ChainID)
	if !c.identified {
		c.identified, c.host, c.boot = true, h.HostUUID, h.BootID
	} else if c.boot != h.BootID {
		out = append(out, f(ChainFork, cid, h.Seq, "chain seen with boot_id %q, this batch says %q", c.boot, h.BootID))
	}

	switch h.Kind {
	case batch.KindEvents:
		if _, err := batch.SplitRecords(b.Payload, h.Count); err != nil {
			out = append(out, f(BadPayload, cid, h.Seq, "%v", err))
		}
	case batch.KindChainReset:
		r, err := batch.ParseReset(b.Payload)
		if err != nil {
			out = append(out, f(BadPayload, cid, h.Seq, "%v", err))
			break
		}
		c.resetReason = r.Reason
		detail := "reason=" + r.Reason
		if r.Prev != nil {
			detail += fmt.Sprintf(" prev=%s/%d/%s", r.Prev.ChainID, r.Prev.Seq, r.Prev.Hash)
			if pc, ok := v.chains[r.Prev.ChainID]; ok {
				if e, ok := pc.entries[r.Prev.Seq]; ok && e.hash != r.Prev.Hash {
					out = append(out, f(ChainFork, r.Prev.ChainID.String(), r.Prev.Seq, "chain_reset names hash %s for this seq; known %s", r.Prev.Hash, e.hash))
				}
			}
		}
		out = append(out, f(ChainReset, cid, h.Seq, "%s", detail))
	case batch.KindDropped:
		d, err := batch.ParseDropped(b.Payload)
		if err != nil {
			out = append(out, f(BadPayload, cid, h.Seq, "%v", err))
			break
		}
		out = append(out, f(Dropped, cid, h.Seq, "class=%s count=%d", d.Class, len(d.Batches)))
		for _, ref := range d.Batches {
			out = append(out, v.declare(idx, ref)...)
		}
	}
	out = append(out, v.receive(idx, c, b)...)
	return out
}

// declare records a dropped record's entry.
func (v *Verifier) declare(idx int, ref batch.Ref) []Finding {
	c := v.chain(ref.ChainID)
	cid := ref.ChainID.String()
	if e, ok := c.entries[ref.Seq]; ok {
		if e.hash != ref.Hash {
			return []Finding{{Kind: ChainFork, Index: idx, ChainID: cid, Seq: ref.Seq, LastSeq: ref.Seq, Detail: fmt.Sprintf("dropped record names hash %s; known %s", ref.Hash, e.hash)}}
		}
		if !e.declared {
			e.declared = true
			c.declared++
		}
		return nil
	}
	c.entries[ref.Seq] = &entry{hash: ref.Hash, declared: true}
	c.declared++
	v.entries++
	if ref.Seq > c.maxSeq {
		c.maxSeq = ref.Seq
	}
	out := v.checkNext(idx, c, ref.Seq)
	c.advance()
	return out
}

// receive records a received batch and checks its links.
func (v *Verifier) receive(idx int, c *chain, b batch.Batch) []Finding {
	h := b.Header
	cid := h.ChainID.String()
	mk := func(k Kind, format string, a ...any) Finding {
		return Finding{Kind: k, Index: idx, ChainID: cid, Seq: h.Seq, LastSeq: h.Seq, Detail: fmt.Sprintf(format, a...)}
	}
	var out []Finding
	if e, ok := c.entries[h.Seq]; ok {
		switch {
		case e.received && e.hash == b.Hash:
			return []Finding{mk(Duplicate, "identical resend")}
		case e.received:
			return []Finding{mk(DuplicateMismatch, "hash %s, first received %s", b.Hash, e.hash), mk(ChainFork, "two batches with seq %d", h.Seq)}
		case e.hash != b.Hash:
			return []Finding{mk(ChainFork, "hash %s, but a dropped record declared %s", b.Hash, e.hash)}
		}
		e.received, e.prev = true, h.PrevHash
		c.received++
	} else {
		if h.Seq < c.maxSeq {
			out = append(out, mk(ChainReorder, "seq %d first seen after seq %d", h.Seq, c.maxSeq))
		}
		c.entries[h.Seq] = &entry{hash: b.Hash, prev: h.PrevHash, received: true}
		c.received++
		v.entries++
		if h.Seq > c.maxSeq {
			c.maxSeq = h.Seq
		}
	}
	if h.Seq > 1 {
		if p, ok := c.entries[h.Seq-1]; ok && p.hash != h.PrevHash {
			out = append(out, mk(ChainFork, "prev_hash %s, but seq %d has hash %s", h.PrevHash, h.Seq-1, p.hash))
		}
	}
	out = append(out, v.checkNext(idx, c, h.Seq)...)
	c.advance()
	return out
}

// checkNext checks the link from seq to seq+1 when seq+1 was received
// first.
func (v *Verifier) checkNext(idx int, c *chain, seq uint64) []Finding {
	n, ok := c.entries[seq+1]
	if !ok || !n.received {
		return nil
	}
	if cur := c.entries[seq]; n.prev != cur.hash {
		return []Finding{{Kind: ChainFork, Index: idx, ChainID: c.id.String(), Seq: seq + 1, LastSeq: seq + 1, Detail: fmt.Sprintf("prev_hash %s, but seq %d has hash %s", n.prev, seq, cur.hash)}}
	}
	return nil
}

func (c *chain) advance() {
	for {
		if _, ok := c.entries[c.contiguous+1]; !ok {
			return
		}
		c.contiguous++
	}
}

// Gaps returns a chain_gap finding for every range of seqs, below the
// highest known seq of its chain, that was neither received nor declared
// dropped. It does not change the Verifier.
func (v *Verifier) Gaps() []Finding {
	var out []Finding
	for _, id := range v.order {
		c := v.chains[id]
		seqs := make([]uint64, 0, len(c.entries))
		for s := range c.entries {
			seqs = append(seqs, s)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		var last uint64
		for _, s := range seqs {
			if s > last+1 {
				out = append(out, Finding{Kind: ChainGap, Index: -1, ChainID: id.String(), Seq: last + 1, LastSeq: s - 1, Detail: fmt.Sprintf("seqs %d..%d neither received nor declared dropped", last+1, s-1)})
			}
			last = s
		}
	}
	return out
}

// Chains summarizes every chain in first-seen order.
func (v *Verifier) Chains() []ChainSummary {
	out := make([]ChainSummary, 0, len(v.order))
	for _, id := range v.order {
		c := v.chains[id]
		out = append(out, ChainSummary{
			ChainID: id.String(), HostUUID: c.host, BootID: c.boot, Contiguous: c.contiguous,
			MaxSeq: c.maxSeq, Received: c.received, Declared: c.declared, ResetReason: c.resetReason,
		})
	}
	return out
}
