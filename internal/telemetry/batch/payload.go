package batch

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// Ref names one batch: its chain, seq and hash.
type Ref struct {
	ChainID ChainID
	Seq     uint64
	Hash    Hash
}

// Dropped is a dropped record's payload (ADR 0039 section 4b): the
// batches the spool deleted to make room, all of one class.
type Dropped struct {
	Class   string
	Batches []Ref
}

// Reset reasons (ADR 0039 section 3).
const (
	ReasonBootChanged   = "boot_changed"
	ReasonHeadMissing   = "head_missing"
	ReasonHeadCorrupt   = "head_corrupt"
	ReasonTamperedMode  = "tampered_mode"
	ReasonBootIDUnknown = "boot_id_unknown"
)

// Reset is a chain_reset payload: why the chain started, and the previous
// chain's last known head if there is one.
type Reset struct {
	Reason string
	Prev   *Ref
}

func validReason(r string) bool {
	switch r {
	case ReasonBootChanged, ReasonHeadMissing, ReasonHeadCorrupt, ReasonTamperedMode, ReasonBootIDUnknown:
		return true
	}
	return false
}

func appendRef(b []byte, r Ref) []byte {
	b = append(b, `{"chain_id":"`...)
	b = append(b, r.ChainID.String()...)
	b = append(b, `","seq":`...)
	b = strconv.AppendUint(b, r.Seq, 10)
	b = append(b, `,"hash":"`...)
	b = append(b, r.Hash.String()...)
	return append(b, `"}`...)
}

// Marshal returns d's canonical JSON.
func (d *Dropped) Marshal() ([]byte, error) {
	if d.Class != ClassSecurity && d.Class != ClassNonSecurity {
		return nil, fmt.Errorf("%w: dropped class %q", ErrBadPayload, d.Class)
	}
	if len(d.Batches) == 0 || len(d.Batches) > limits.MaxDroppedEntriesPerRecord {
		return nil, fmt.Errorf("%w: dropped record with %d entries (1..%d)", ErrBadPayload, len(d.Batches), limits.MaxDroppedEntriesPerRecord)
	}
	b := append([]byte(`{"class":"`), d.Class...)
	b = append(b, `","count":`...)
	b = strconv.AppendInt(b, int64(len(d.Batches)), 10)
	b = append(b, `,"batches":[`...)
	for i, r := range d.Batches {
		if r.Seq == 0 {
			return nil, fmt.Errorf("%w: dropped entry with seq 0", ErrBadPayload)
		}
		if i > 0 {
			b = append(b, ',')
		}
		b = appendRef(b, r)
	}
	return append(b, `]}`...), nil
}

type wireRef struct {
	ChainID string `json:"chain_id"`
	Seq     uint64 `json:"seq"`
	Hash    string `json:"hash"`
}

func (w wireRef) ref() (Ref, error) {
	var r Ref
	r.Seq = w.Seq
	if !decodeHex(r.ChainID[:], w.ChainID) || !decodeHex(r.Hash[:], w.Hash) {
		return Ref{}, fmt.Errorf("%w: ref hex field", ErrBadPayload)
	}
	return r, nil
}

// ParseDropped parses a dropped payload, accepting only its canonical
// form.
func ParseDropped(raw []byte) (Dropped, error) {
	var w struct {
		Class   string    `json:"class"`
		Count   int       `json:"count"`
		Batches []wireRef `json:"batches"`
	}
	if len(raw) > limits.MaxTelemetryPayloadBytes {
		return Dropped{}, fmt.Errorf("%w: dropped payload too large", ErrBadPayload)
	}
	if err := strictjson.DecodeStrict(raw, 4, &w); err != nil {
		return Dropped{}, fmt.Errorf("%w: %w", ErrBadPayload, err)
	}
	if w.Count != len(w.Batches) {
		return Dropped{}, fmt.Errorf("%w: dropped count %d but %d entries", ErrBadPayload, w.Count, len(w.Batches))
	}
	d := Dropped{Class: w.Class}
	for _, e := range w.Batches {
		r, err := e.ref()
		if err != nil {
			return Dropped{}, err
		}
		d.Batches = append(d.Batches, r)
	}
	canon, err := d.Marshal()
	if err != nil {
		return Dropped{}, err
	}
	if string(canon) != string(raw) {
		return Dropped{}, fmt.Errorf("%w: dropped payload not canonical", ErrBadPayload)
	}
	return d, nil
}

// Marshal returns r's canonical JSON.
func (r *Reset) Marshal() ([]byte, error) {
	if !validReason(r.Reason) {
		return nil, fmt.Errorf("%w: reset reason %q", ErrBadPayload, r.Reason)
	}
	b := append([]byte(`{"reason":"`), r.Reason...)
	b = append(b, `","prev":`...)
	if r.Prev == nil {
		b = append(b, `null`...)
	} else {
		if r.Prev.Seq == 0 {
			return nil, fmt.Errorf("%w: reset prev with seq 0", ErrBadPayload)
		}
		b = appendRef(b, *r.Prev)
	}
	return append(b, '}'), nil
}

// ParseReset parses a chain_reset payload, accepting only its canonical
// form.
func ParseReset(raw []byte) (Reset, error) {
	var w struct {
		Reason string   `json:"reason"`
		Prev   *wireRef `json:"prev"`
	}
	if len(raw) > limits.MaxTelemetryHeaderBytes {
		return Reset{}, fmt.Errorf("%w: reset payload too large", ErrBadPayload)
	}
	if err := strictjson.DecodeStrict(raw, 3, &w); err != nil {
		return Reset{}, fmt.Errorf("%w: %w", ErrBadPayload, err)
	}
	r := Reset{Reason: w.Reason}
	if w.Prev != nil {
		ref, err := w.Prev.ref()
		if err != nil {
			return Reset{}, err
		}
		r.Prev = &ref
	}
	canon, err := r.Marshal()
	if err != nil {
		return Reset{}, err
	}
	if string(canon) != string(raw) {
		return Reset{}, fmt.Errorf("%w: reset payload not canonical", ErrBadPayload)
	}
	return r, nil
}

// AppendRecord appends one length-prefixed event record to payload.
func AppendRecord(payload, record []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(record))) //nolint:gosec // G115: records are bounded by MaxTelemetryEventBytes
	payload = append(payload, n[:]...)
	return append(payload, record...)
}

// RecordOverhead is the bytes AppendRecord adds besides the record.
const RecordOverhead = 4

// SplitRecords splits an events payload into its records. It fails
// unless the payload is exactly a sequence of want non-empty records,
// none larger than limits.MaxTelemetryEventBytes.
func SplitRecords(payload []byte, want uint64) ([][]byte, error) {
	if want == 0 || want > uint64(len(payload))/(RecordOverhead+1) {
		return nil, fmt.Errorf("%w: %d records cannot fit %d bytes", ErrBadPayload, want, len(payload))
	}
	out := make([][]byte, 0, want)
	for len(payload) > 0 {
		if len(payload) < RecordOverhead {
			return nil, fmt.Errorf("%w: truncated record length", ErrBadPayload)
		}
		n := binary.BigEndian.Uint32(payload)
		payload = payload[RecordOverhead:]
		if n == 0 || n > limits.MaxTelemetryEventBytes || uint64(n) > uint64(len(payload)) {
			return nil, fmt.Errorf("%w: record length %d", ErrBadPayload, n)
		}
		out = append(out, payload[:n])
		payload = payload[n:]
	}
	if uint64(len(out)) != want {
		return nil, fmt.Errorf("%w: %d records, header count %d", ErrBadPayload, len(out), want)
	}
	return out, nil
}
