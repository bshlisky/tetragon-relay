// Package batchtest builds valid telemetry chains for tests (the
// reference verifier's table tests, the pipeline's tests and the fuzz
// corpora). Test support only: nothing outside _test files and test
// tools imports it.
package batchtest

import (
	"crypto/sha256"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/batch"
)

// Host is the host UUID every chain built here carries.
const Host = "11111111-1111-1111-1111-111111111111"

// Chain builds consecutive batches of one chain.
type Chain struct {
	ID   batch.ChainID
	Boot string
	// V is the header version of the batches built next (0: current).
	V    int
	seq  uint64
	prev batch.Hash
	ts   int64
}

// NewChain starts a chain with the given id byte and boot ID.
func NewChain(id byte, boot string) *Chain {
	return &Chain{ID: batch.ChainID{id}, Boot: boot}
}

// Built is one batch as sent.
type Built struct {
	Header  []byte
	Payload []byte
	Hash    batch.Hash
	Seq     uint64
}

// Ref returns b's reference in chain c.
func (c *Chain) Ref(b Built) batch.Ref { return batch.Ref{ChainID: c.ID, Seq: b.Seq, Hash: b.Hash} }

func (c *Chain) next(kind, class string, count uint64, payload []byte) Built {
	enc := batch.EncNone
	if c.V == batch.VersionV1 {
		enc = ""
	}
	return c.nextEnc(kind, class, count, payload, enc)
}

func (c *Chain) nextEnc(kind, class string, count uint64, payload []byte, enc string) Built {
	c.seq++
	c.ts += 1000
	h := batch.Header{
		V:        c.V,
		HostUUID: Host, BootID: c.Boot, ChainID: c.ID, Seq: c.seq, PrevHash: c.prev,
		Kind: kind, Class: class, Count: count, FirstTS: c.ts, LastTS: c.ts + 10,
		AgentVersion: "test", Epochs: map[string]uint64{"prod": 1}, Enc: enc, PayloadSHA256: sha256.Sum256(payload),
	}
	raw, err := h.Marshal()
	if err != nil {
		panic(err)
	}
	b := Built{Header: raw, Payload: payload, Hash: batch.HashOf(raw, payload), Seq: c.seq}
	c.prev = b.Hash
	return b
}

// Reset builds seq 1, a chain_reset.
func (c *Chain) Reset(reason string, prev *batch.Ref) Built {
	p, err := (&batch.Reset{Reason: reason, Prev: prev}).Marshal()
	if err != nil {
		panic(err)
	}
	return c.next(batch.KindChainReset, batch.ClassControl, 0, p)
}

// Events builds an events batch with n one-byte records.
func (c *Chain) Events(class string, n int) Built {
	var p []byte
	for i := 0; i < n; i++ {
		p = batch.AppendRecord(p, []byte{byte(i)})
	}
	return c.next(batch.KindEvents, class, uint64(n), p) //nolint:gosec // G115: test sizes
}

// EventsZstd builds an events batch of count records whose payload as
// sent is z, declared enc "zstd" (z is not checked: tests pass bombs).
func (c *Chain) EventsZstd(class string, count uint64, z []byte) Built {
	return c.nextEnc(batch.KindEvents, class, count, z, batch.EncZstd)
}

// Dropped builds a dropped record listing refs.
func (c *Chain) Dropped(class string, refs ...batch.Ref) Built {
	p, err := (&batch.Dropped{Class: class, Batches: refs}).Marshal()
	if err != nil {
		panic(err)
	}
	return c.next(batch.KindDropped, batch.ClassControl, 0, p)
}
