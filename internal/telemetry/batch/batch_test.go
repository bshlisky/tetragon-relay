package batch

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

func sampleHeader() Header {
	return Header{
		HostUUID: "11111111-1111-1111-1111-111111111111", BootID: "b0", ChainID: ChainID{1, 2, 3},
		Seq: 2, PrevHash: Hash{9}, Kind: KindEvents, Class: ClassSecurity, Count: 3,
		FirstTS: 10, LastTS: 20, AgentVersion: "v0.7.0", Epochs: map[string]uint64{"z": 1, "a": 5},
		TelemetryPolicyEpoch: 4, Enc: EncZstd, PayloadSHA256: Hash{7},
	}
}

// v1Sample is sampleHeader as a step 7a agent wrote it.
func v1Sample() Header {
	h := sampleHeader()
	h.V, h.TelemetryPolicyEpoch, h.Enc = VersionV1, 0, ""
	return h
}

const v1Canonical = `{"v":1,"host_uuid":"11111111-1111-1111-1111-111111111111","boot_id":"b0","chain_id":"01020300000000000000000000000000","seq":2,"prev_hash":"0900000000000000000000000000000000000000000000000000000000000000","kind":"events","class":"security","count":3,"first_ts":10,"last_ts":20,"agent_version":"v0.7.0","epochs":{"a":5,"z":1},"payload_sha256":"0700000000000000000000000000000000000000000000000000000000000000"}`

// A 7a header still parses, keeps v1 and re-serializes to the same bytes;
// its encoding is none.
func TestHeader_V1StillAccepted(t *testing.T) {
	h := v1Sample()
	raw, err := h.Marshal()
	if err != nil || string(raw) != v1Canonical {
		t.Fatalf("v1 marshal: %v\n got %s", err, raw)
	}
	got, err := ParseHeader([]byte(v1Canonical))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version() != VersionV1 || got.Encoding() != EncNone || got.TelemetryPolicyEpoch != 0 {
		t.Fatalf("v1 parsed as %+v", got)
	}
	again, _ := got.Marshal()
	if string(again) != v1Canonical {
		t.Fatal("v1 round trip changed the bytes")
	}
	for name, in := range map[string]string{
		"v1 with enc":        strings.Replace(v1Canonical, `,"payload_sha256"`, `,"enc":"none","payload_sha256"`, 1),
		"v1 with tpe":        strings.Replace(v1Canonical, `,"payload_sha256"`, `,"telemetry_policy_epoch":0,"payload_sha256"`, 1),
		"v1 relabelled as 2": strings.Replace(v1Canonical, `"v":1`, `"v":2`, 1),
	} {
		if _, err := ParseHeader([]byte(in)); !errors.Is(err, ErrBadHeader) {
			t.Errorf("%s: err = %v, want ErrBadHeader", name, err)
		}
	}
	bad := v1Sample()
	bad.Enc = EncZstd
	if _, err := bad.Marshal(); !errors.Is(err, ErrBadHeader) {
		t.Error("v1 header with enc marshaled")
	}
}

func TestHeader_CanonicalRoundTrip(t *testing.T) {
	h := sampleHeader()
	raw, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":2,"host_uuid":"11111111-1111-1111-1111-111111111111","boot_id":"b0","chain_id":"01020300000000000000000000000000","seq":2,"prev_hash":"0900000000000000000000000000000000000000000000000000000000000000","kind":"events","class":"security","count":3,"first_ts":10,"last_ts":20,"agent_version":"v0.7.0","epochs":{"a":5,"z":1},"telemetry_policy_epoch":4,"enc":"zstd","payload_sha256":"0700000000000000000000000000000000000000000000000000000000000000"}`
	if string(raw) != want {
		t.Fatalf("canonical form:\n got %s\nwant %s", raw, want)
	}
	got, err := ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := got.Marshal()
	if string(again) != want {
		t.Fatal("round trip changed the bytes")
	}
	empty := sampleHeader()
	empty.Epochs = map[string]uint64{}
	raw, _ = empty.Marshal()
	if !strings.Contains(string(raw), `"epochs":{}`) {
		t.Fatalf("empty epochs: %s", raw)
	}
	if _, err := ParseHeader(raw); err != nil {
		t.Fatal(err)
	}
}

func TestParseHeader_RejectsNonCanonical(t *testing.T) {
	h := sampleHeader()
	raw, _ := h.Marshal()
	s := string(raw)
	cases := map[string]string{
		"whitespace":      strings.Replace(s, `"seq":2`, `"seq": 2`, 1),
		"key order":       strings.Replace(s, `{"v":2,"host_uuid":"11111111-1111-1111-1111-111111111111"`, `{"host_uuid":"11111111-1111-1111-1111-111111111111","v":2`, 1),
		"enc order":       strings.Replace(s, `"telemetry_policy_epoch":4,"enc":"zstd"`, `"enc":"zstd","telemetry_policy_epoch":4`, 1),
		"enc missing":     strings.Replace(s, `,"enc":"zstd"`, ``, 1),
		"tpe missing":     strings.Replace(s, `,"telemetry_policy_epoch":4`, ``, 1),
		"enc unknown":     strings.Replace(s, `"enc":"zstd"`, `"enc":"gzip"`, 1),
		"enc empty":       strings.Replace(s, `"enc":"zstd"`, `"enc":""`, 1),
		"v2 as v1":        strings.Replace(s, `"v":2`, `"v":1`, 1),
		"upper hex":       strings.Replace(s, `"chain_id":"0102`, `"chain_id":"0A02`, 1),
		"duplicate key":   strings.Replace(s, `"seq":2`, `"seq":2,"seq":2`, 1),
		"unknown key":     strings.Replace(s, `"seq":2`, `"seq":2,"x":1`, 1),
		"escape":          strings.Replace(s, `"boot_id":"b0"`, `"boot_id":"\u00620"`, 1),
		"float":           strings.Replace(s, `"seq":2`, `"seq":2.0`, 1),
		"leading zero":    strings.Replace(s, `"count":3`, `"count":03`, 1),
		"version":         strings.Replace(s, `"v":2`, `"v":3`, 1),
		"version 0":       strings.Replace(s, `"v":2`, `"v":0`, 1),
		"short hex":       strings.Replace(s, `"chain_id":"01020300000000000000000000000000"`, `"chain_id":"0102"`, 1),
		"epochs unsorted": strings.Replace(s, `{"a":5,"z":1}`, `{"z":1,"a":5}`, 1),
		"epochs missing":  strings.Replace(s, `,"epochs":{"a":5,"z":1}`, ``, 1),
		"trailing":        s + " ",
		"empty":           "",
		"not json":        "{",
	}
	for name, in := range cases {
		if _, err := ParseHeader([]byte(in)); !errors.Is(err, ErrBadHeader) {
			t.Errorf("%s: err = %v, want ErrBadHeader", name, err)
		}
	}
	if _, err := ParseHeader([]byte(strings.Repeat(" ", limits.MaxTelemetryHeaderBytes+1))); !errors.Is(err, ErrBadHeader) {
		t.Error("oversized header accepted")
	}
}

func TestHeader_Validate(t *testing.T) {
	mut := map[string]func(*Header){
		"no host":            func(h *Header) { h.HostUUID = "" },
		"quote in host":      func(h *Header) { h.HostUUID = `a"b` },
		"control char boot":  func(h *Header) { h.BootID = "a\nb" },
		"no version":         func(h *Header) { h.AgentVersion = "" },
		"long version":       func(h *Header) { h.AgentVersion = strings.Repeat("a", limits.MaxTelemetryStringBytes+1) },
		"seq 0":              func(h *Header) { h.Seq = 0 },
		"ts order":           func(h *Header) { h.FirstTS = 30 },
		"bad scope":          func(h *Header) { h.Epochs = map[string]uint64{"": 1} },
		"events class":       func(h *Header) { h.Class = ClassControl },
		"events count 0":     func(h *Header) { h.Count = 0 },
		"control count":      func(h *Header) { h.Kind = KindDropped; h.Class = ClassControl },
		"control class":      func(h *Header) { h.Kind = KindDropped; h.Count = 0 },
		"kind":               func(h *Header) { h.Kind = "other" },
		"reset not seq 1":    func(h *Header) { h.Kind = KindChainReset; h.Class = ClassControl; h.Count = 0 },
		"seq 1 not reset":    func(h *Header) { h.Seq = 1; h.PrevHash = Hash{} },
		"seq 1 prev_hash":    func(h *Header) { h.Seq = 1; h.Kind = KindChainReset; h.Class = ClassControl; h.Count = 0 },
		"too many scopes":    func(h *Header) { h.Epochs = manyScopes(limits.MaxTelemetryEpochScopes + 1) },
		"oversized marshal":  func(h *Header) { h.Epochs = manyScopes(limits.MaxTelemetryEpochScopes); h.AgentVersion = "x" },
		"non-printable vers": func(h *Header) { h.AgentVersion = "\x7f" },
		"v2 no enc":          func(h *Header) { h.Enc = "" },
		"enc unknown":        func(h *Header) { h.Enc = "lz4" },
		"zstd control": func(h *Header) {
			h.Seq = 1
			h.PrevHash = Hash{}
			h.Kind = KindChainReset
			h.Class = ClassControl
			h.Count = 0
		},
		"version 3":  func(h *Header) { h.V = 3 },
		"version -1": func(h *Header) { h.V = -1 },
	}
	for name, m := range mut {
		h := sampleHeader()
		m(&h)
		if _, err := h.Marshal(); name != "oversized marshal" && !errors.Is(err, ErrBadHeader) {
			t.Errorf("%s: Marshal err = %v", name, err)
		}
	}
	ok := sampleHeader()
	ok.Seq, ok.PrevHash, ok.Kind, ok.Class, ok.Count, ok.Enc = 1, Hash{}, KindChainReset, ClassControl, 0, EncNone
	if _, err := ok.Marshal(); err != nil {
		t.Fatalf("valid chain_reset header: %v", err)
	}
}

func manyScopes(n int) map[string]uint64 {
	m := map[string]uint64{}
	for i := 0; i < n; i++ {
		m[strings.Repeat("s", 100)+string(rune('A'+i%26))+string(rune('A'+i/26))] = 1 << 60
	}
	return m
}

func TestHashOf_Vector(t *testing.T) {
	header, payload := []byte("hdr"), []byte("payload")
	buf := []byte{0, 0, 0, 3}
	buf = append(buf, header...)
	buf = append(buf, payload...)
	if HashOf(header, payload) != Hash(sha256.Sum256(buf)) {
		t.Fatal("HashOf is not SHA-256(be32(len(header)) || header || payload)")
	}
	// Moving a byte between header and payload changes the hash.
	if HashOf([]byte("hd"), []byte("rpayload")) == HashOf(header, payload) {
		t.Fatal("length prefix does not separate header from payload")
	}
}

func TestParse(t *testing.T) {
	payload := AppendRecord(nil, []byte("event"))
	h := sampleHeader()
	h.Count = 1
	h.PayloadSHA256 = sha256.Sum256(payload)
	raw, _ := h.Marshal()
	b, err := Parse(raw, payload)
	if err != nil {
		t.Fatal(err)
	}
	if b.Hash != HashOf(raw, payload) || b.Header.Seq != 2 {
		t.Fatalf("parsed %+v", b)
	}
	if _, err := Parse(raw, append(payload, 0)); !errors.Is(err, ErrPayloadDigest) {
		t.Fatalf("tampered payload: %v", err)
	}
	if _, err := Parse(raw, make([]byte, limits.MaxTelemetryPayloadBytes+1)); !errors.Is(err, ErrBadPayload) {
		t.Fatalf("oversized payload: %v", err)
	}
	if _, err := Parse([]byte("{}"), payload); !errors.Is(err, ErrBadHeader) {
		t.Fatalf("bad header: %v", err)
	}
}

func TestDropped(t *testing.T) {
	d := Dropped{Class: ClassNonSecurity, Batches: []Ref{{ChainID: ChainID{1}, Seq: 7, Hash: Hash{2}}, {ChainID: ChainID{1}, Seq: 9, Hash: Hash{3}}}}
	raw, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDropped(raw)
	if err != nil || len(got.Batches) != 2 || got.Batches[1].Seq != 9 || got.Class != ClassNonSecurity {
		t.Fatalf("ParseDropped: %+v %v", got, err)
	}
	s := string(raw)
	for name, in := range map[string]string{
		"count":       strings.Replace(s, `"count":2`, `"count":3`, 1),
		"class":       strings.Replace(s, `"non_security"`, `"control"`, 1),
		"space":       strings.Replace(s, `"count":2`, `"count": 2`, 1),
		"hex":         strings.Replace(s, `"hash":"02`, `"hash":"zz`, 1),
		"seq 0":       strings.Replace(s, `"seq":7`, `"seq":0`, 1),
		"unknown key": strings.Replace(s, `"count":2`, `"count":2,"x":1`, 1),
		"not json":    "[",
	} {
		if _, err := ParseDropped([]byte(in)); !errors.Is(err, ErrBadPayload) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]Dropped{
		"empty":     {Class: ClassSecurity},
		"too many":  {Class: ClassSecurity, Batches: make([]Ref, limits.MaxDroppedEntriesPerRecord+1)},
		"bad class": {Class: "x", Batches: []Ref{{Seq: 1}}},
		"seq 0":     {Class: ClassSecurity, Batches: []Ref{{}}},
	} {
		if _, err := bad.Marshal(); !errors.Is(err, ErrBadPayload) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseDropped(make([]byte, limits.MaxTelemetryPayloadBytes+1)); !errors.Is(err, ErrBadPayload) {
		t.Error("oversized dropped payload accepted")
	}
}

func TestReset(t *testing.T) {
	for _, r := range []Reset{
		{Reason: ReasonHeadMissing},
		{Reason: ReasonBootChanged, Prev: &Ref{ChainID: ChainID{5}, Seq: 41, Hash: Hash{6}}},
		{Reason: ReasonHeadCorrupt}, {Reason: ReasonTamperedMode}, {Reason: ReasonBootIDUnknown},
	} {
		raw, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseReset(raw)
		if err != nil || got.Reason != r.Reason || (got.Prev == nil) != (r.Prev == nil) {
			t.Fatalf("ParseReset(%s): %+v %v", raw, got, err)
		}
	}
	for name, in := range map[string]string{
		"reason":   `{"reason":"other","prev":null}`,
		"space":    `{"reason":"head_missing", "prev":null}`,
		"prev hex": `{"reason":"boot_changed","prev":{"chain_id":"x","seq":1,"hash":"y"}}`,
		"prev 0":   `{"reason":"boot_changed","prev":{"chain_id":"00000000000000000000000000000000","seq":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000"}}`,
		"json":     `{`,
		"big":      strings.Repeat("a", limits.MaxTelemetryHeaderBytes+1),
	} {
		if _, err := ParseReset([]byte(in)); !errors.Is(err, ErrBadPayload) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSplitRecords(t *testing.T) {
	var p []byte
	p = AppendRecord(p, []byte("a"))
	p = AppendRecord(p, []byte("bc"))
	recs, err := SplitRecords(p, 2)
	if err != nil || len(recs) != 2 || string(recs[1]) != "bc" {
		t.Fatalf("SplitRecords: %q %v", recs, err)
	}
	big := make([]byte, 8)
	binary.BigEndian.PutUint32(big, limits.MaxTelemetryEventBytes+1)
	zero := []byte{0, 0, 0, 0, 0}
	for name, c := range map[string]struct {
		p []byte
		n uint64
	}{
		"count high":  {p, 3},
		"count low":   {p, 1},
		"count zero":  {p, 0},
		"truncated":   {p[:len(p)-1], 2},
		"short len":   {append(AppendRecord(nil, []byte("abcd")), 0, 0), 2},
		"zero length": {zero, 1},
		"oversized":   {big, 1},
		"empty":       {nil, 1},
	} {
		if _, err := SplitRecords(c.p, c.n); !errors.Is(err, ErrBadPayload) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if ChainID([16]byte{0xab}).String()[:2] != "ab" || (Hash{0xcd}).String()[:2] != "cd" {
		t.Fatal("hex String")
	}
}

func TestDropped_RateLimited(t *testing.T) {
	d := Dropped{Class: ClassNonSecurity, Reason: DropRateLimited, Events: 1234}
	raw, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"class":"non_security","reason":"rate_limited","events":1234}`; string(raw) != want {
		t.Fatalf("Marshal = %s, want %s", raw, want)
	}
	got, err := ParseDropped(raw)
	if err != nil || got.Reason != DropRateLimited || got.Events != 1234 || got.Class != ClassNonSecurity || len(got.Batches) != 0 {
		t.Fatalf("ParseDropped: %+v %v", got, err)
	}
	s := string(raw)
	for name, in := range map[string]string{
		"security class": strings.Replace(s, `"non_security"`, `"security"`, 1),
		"zero events":    strings.Replace(s, `1234`, `0`, 1),
		"negative":       strings.Replace(s, `1234`, `-1`, 1),
		"reason":         strings.Replace(s, `rate_limited`, `spool_overflow`, 1),
		"order":          `{"class":"non_security","events":1234,"reason":"rate_limited"}`,
		"with count":     strings.Replace(s, `}`, `,"count":0}`, 1),
		"with batches":   strings.Replace(s, `}`, `,"batches":[]}`, 1),
		"unknown key":    strings.Replace(s, `}`, `,"x":1}`, 1),
		"overflow+events": `{"class":"non_security","count":1,"batches":[{"chain_id":"` + strings.Repeat("01", 16) +
			`","seq":7,"hash":"` + strings.Repeat("02", 32) + `"}],"events":3}`,
	} {
		if _, err := ParseDropped([]byte(in)); !errors.Is(err, ErrBadPayload) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]Dropped{
		"security":       {Class: ClassSecurity, Reason: DropRateLimited, Events: 1},
		"no events":      {Class: ClassNonSecurity, Reason: DropRateLimited},
		"with batches":   {Class: ClassNonSecurity, Reason: DropRateLimited, Events: 1, Batches: []Ref{{Seq: 1}}},
		"unknown reason": {Class: ClassNonSecurity, Reason: "x", Events: 1},
		"overflow+count": {Class: ClassNonSecurity, Events: 1, Batches: []Ref{{Seq: 1}}},
	} {
		if _, err := bad.Marshal(); !errors.Is(err, ErrBadPayload) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
