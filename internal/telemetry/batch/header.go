// Package batch is the telemetry wire format of ADR 0039: the canonical
// batch header, the batch hash, and the payloads of the control kinds
// (dropped, chain_reset) and of events (length-prefixed records). Both the
// agent's pipeline (internal/telemetry) and the reference chain verifier
// (internal/telemetry/chainverify) use it, so there is one definition of
// the format. It has no I/O, no clock and no global state.
package batch

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/strictjson"
)

// Version is the header's "v".
const Version = 1

// Kinds.
const (
	KindEvents     = "events"
	KindDropped    = "dropped"
	KindChainReset = "chain_reset"
)

// Classes. Events are batched per class; control batches (dropped,
// chain_reset) are ClassControl and are never dropped on overflow.
const (
	ClassSecurity    = "security"
	ClassNonSecurity = "non_security"
	ClassControl     = "control"
)

// ErrBadHeader wraps every header rejection.
var ErrBadHeader = errors.New("batch: bad header")

// ErrBadPayload wraps every payload rejection.
var ErrBadPayload = errors.New("batch: bad payload")

// ChainID is a chain's random 128-bit identifier.
type ChainID [16]byte

// String is the header's lower-case hex form.
func (c ChainID) String() string { return hex.EncodeToString(c[:]) }

// Hash is a batch hash (and payload_sha256).
type Hash [32]byte

// String is the header's lower-case hex form.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// Header is a batch header. Marshal produces its canonical JSON;
// ParseHeader accepts only that exact form.
type Header struct {
	HostUUID      string
	BootID        string
	ChainID       ChainID
	Seq           uint64
	PrevHash      Hash
	Kind          string
	Class         string
	Count         uint64
	FirstTS       int64
	LastTS        int64
	AgentVersion  string
	Epochs        map[string]uint64
	PayloadSHA256 Hash
}

// safeString reports whether s may appear in a header unescaped: 1..max
// bytes of printable ASCII other than '"' and '\\' (empty allowed when
// allowEmpty).
func safeString(s string, allowEmpty bool) bool {
	if s == "" {
		return allowEmpty
	}
	if len(s) > limits.MaxTelemetryStringBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// Validate checks every field rule of ADR 0039 section 2 that does not
// depend on the payload.
func (h *Header) Validate() error {
	switch {
	case !safeString(h.HostUUID, false):
		return fmt.Errorf("%w: host_uuid", ErrBadHeader)
	case !safeString(h.BootID, true):
		return fmt.Errorf("%w: boot_id", ErrBadHeader)
	case !safeString(h.AgentVersion, false):
		return fmt.Errorf("%w: agent_version", ErrBadHeader)
	case h.Seq == 0:
		return fmt.Errorf("%w: seq must be >= 1", ErrBadHeader)
	case h.Seq == 1 && h.PrevHash != (Hash{}):
		return fmt.Errorf("%w: seq 1 must have a zero prev_hash", ErrBadHeader)
	case h.FirstTS > h.LastTS:
		return fmt.Errorf("%w: first_ts after last_ts", ErrBadHeader)
	case len(h.Epochs) > limits.MaxTelemetryEpochScopes:
		return fmt.Errorf("%w: %d epoch scopes, max %d", ErrBadHeader, len(h.Epochs), limits.MaxTelemetryEpochScopes)
	}
	for scope := range h.Epochs {
		if !safeString(scope, false) {
			return fmt.Errorf("%w: epochs scope name", ErrBadHeader)
		}
	}
	switch h.Kind {
	case KindEvents:
		if h.Class != ClassSecurity && h.Class != ClassNonSecurity {
			return fmt.Errorf("%w: events batch with class %q", ErrBadHeader, h.Class)
		}
		if h.Count == 0 {
			return fmt.Errorf("%w: events batch with count 0", ErrBadHeader)
		}
	case KindDropped, KindChainReset:
		if h.Class != ClassControl || h.Count != 0 {
			return fmt.Errorf("%w: %s batch must be class control with count 0", ErrBadHeader, h.Kind)
		}
	default:
		return fmt.Errorf("%w: kind %q", ErrBadHeader, h.Kind)
	}
	if (h.Kind == KindChainReset) != (h.Seq == 1) {
		return fmt.Errorf("%w: chain_reset is exactly seq 1", ErrBadHeader)
	}
	return nil
}

// Marshal returns h's canonical JSON. It fails if h does not validate.
func (h *Header) Marshal() ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 0, 512)
	b = append(b, `{"v":`...)
	b = strconv.AppendInt(b, Version, 10)
	b = appendStr(b, "host_uuid", h.HostUUID)
	b = appendStr(b, "boot_id", h.BootID)
	b = appendStr(b, "chain_id", h.ChainID.String())
	b = appendUint(b, "seq", h.Seq)
	b = appendStr(b, "prev_hash", h.PrevHash.String())
	b = appendStr(b, "kind", h.Kind)
	b = appendStr(b, "class", h.Class)
	b = appendUint(b, "count", h.Count)
	b = append(b, `,"first_ts":`...)
	b = strconv.AppendInt(b, h.FirstTS, 10)
	b = append(b, `,"last_ts":`...)
	b = strconv.AppendInt(b, h.LastTS, 10)
	b = appendStr(b, "agent_version", h.AgentVersion)
	b = append(b, `,"epochs":{`...)
	scopes := make([]string, 0, len(h.Epochs))
	for s := range h.Epochs {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	for i, s := range scopes {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '"')
		b = append(b, s...)
		b = append(b, `":`...)
		b = strconv.AppendUint(b, h.Epochs[s], 10)
	}
	b = append(b, '}')
	b = appendStr(b, "payload_sha256", h.PayloadSHA256.String())
	b = append(b, '}')
	if len(b) > limits.MaxTelemetryHeaderBytes {
		return nil, fmt.Errorf("%w: %d bytes, max %d", ErrBadHeader, len(b), limits.MaxTelemetryHeaderBytes)
	}
	return b, nil
}

func appendStr(b []byte, key, val string) []byte {
	b = append(b, `,"`...)
	b = append(b, key...)
	b = append(b, `":"`...)
	b = append(b, val...)
	return append(b, '"')
}

func appendUint(b []byte, key string, v uint64) []byte {
	b = append(b, `,"`...)
	b = append(b, key...)
	b = append(b, `":`...)
	return strconv.AppendUint(b, v, 10)
}

// wireHeader is the strict-decoding shape of a header.
type wireHeader struct {
	V             int               `json:"v"`
	HostUUID      string            `json:"host_uuid"`
	BootID        string            `json:"boot_id"`
	ChainID       string            `json:"chain_id"`
	Seq           uint64            `json:"seq"`
	PrevHash      string            `json:"prev_hash"`
	Kind          string            `json:"kind"`
	Class         string            `json:"class"`
	Count         uint64            `json:"count"`
	FirstTS       int64             `json:"first_ts"`
	LastTS        int64             `json:"last_ts"`
	AgentVersion  string            `json:"agent_version"`
	Epochs        map[string]uint64 `json:"epochs"`
	PayloadSHA256 string            `json:"payload_sha256"`
}

func decodeHex(dst []byte, s string) bool {
	if len(s) != 2*len(dst) {
		return false
	}
	_, err := hex.Decode(dst, []byte(s))
	return err == nil
}

// ParseHeader parses raw strictly and accepts it only if it is exactly
// Marshal's canonical output for the parsed value (key order, no
// whitespace, lower-case hex, no escapes, no duplicates or unknown keys).
func ParseHeader(raw []byte) (Header, error) {
	if len(raw) == 0 || len(raw) > limits.MaxTelemetryHeaderBytes {
		return Header{}, fmt.Errorf("%w: %d bytes", ErrBadHeader, len(raw))
	}
	var w wireHeader
	if err := strictjson.DecodeStrict(raw, 3, &w); err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrBadHeader, err)
	}
	if w.V != Version {
		return Header{}, fmt.Errorf("%w: v=%d", ErrBadHeader, w.V)
	}
	h := Header{
		HostUUID: w.HostUUID, BootID: w.BootID, Seq: w.Seq, Kind: w.Kind, Class: w.Class,
		Count: w.Count, FirstTS: w.FirstTS, LastTS: w.LastTS, AgentVersion: w.AgentVersion, Epochs: w.Epochs,
	}
	if h.Epochs == nil {
		return Header{}, fmt.Errorf("%w: epochs missing", ErrBadHeader)
	}
	if !decodeHex(h.ChainID[:], w.ChainID) || !decodeHex(h.PrevHash[:], w.PrevHash) || !decodeHex(h.PayloadSHA256[:], w.PayloadSHA256) {
		return Header{}, fmt.Errorf("%w: hex field", ErrBadHeader)
	}
	canon, err := h.Marshal()
	if err != nil {
		return Header{}, err
	}
	if string(canon) != string(raw) {
		return Header{}, fmt.Errorf("%w: not canonical", ErrBadHeader)
	}
	return h, nil
}

// HashOf is the batch hash: SHA-256(uint32_be(len(header)) || header ||
// payload).
func HashOf(header, payload []byte) Hash {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(header))) //nolint:gosec // G115: header length is bounded by MaxTelemetryHeaderBytes
	d := sha256.New()
	d.Write(n[:])
	d.Write(header)
	d.Write(payload)
	var h Hash
	d.Sum(h[:0])
	return h
}

// Batch is a parsed batch: the exact bytes plus the parsed header and its
// hash.
type Batch struct {
	Header    Header
	RawHeader []byte
	Payload   []byte
	Hash      Hash
}

// Parse parses a batch as received: a canonical header whose
// payload_sha256 matches payload, and a payload no larger than
// limits.MaxTelemetryPayloadBytes. ErrPayloadDigest is returned (wrapped)
// when only the payload digest is wrong.
func Parse(header, payload []byte) (Batch, error) {
	h, err := ParseHeader(header)
	if err != nil {
		return Batch{}, err
	}
	if len(payload) > limits.MaxTelemetryPayloadBytes {
		return Batch{}, fmt.Errorf("%w: payload %d bytes, max %d", ErrBadPayload, len(payload), limits.MaxTelemetryPayloadBytes)
	}
	if Hash(sha256.Sum256(payload)) != h.PayloadSHA256 {
		return Batch{}, ErrPayloadDigest
	}
	return Batch{Header: h, RawHeader: header, Payload: payload, Hash: HashOf(header, payload)}, nil
}

// ErrPayloadDigest means SHA-256(payload) != header.payload_sha256.
var ErrPayloadDigest = errors.New("batch: payload_sha256 does not match the payload")
