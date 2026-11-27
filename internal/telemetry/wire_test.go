package telemetry

import (
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/bshlisky/tetragon-relay/internal/telemetry/internal/redactgen"
	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// --- the oracle: proto.Unmarshal, plus the rewriter's documented extra
// rejections, checked by a scan that walks the descriptors directly (not
// the rewriter's plan) ---

var (
	errScanType  = errors.New("scan: known field with the wrong wire type")
	errScanDepth = errors.New("scan: too deep")
	errScanOneof = errors.New("scan: two fields of one oneof")
)

func wantWireType(fd protoreflect.FieldDescriptor) protowire.Type {
	switch fd.Kind() { //nolint:exhaustive // the rest are length-delimited
	case protoreflect.BoolKind, protoreflect.EnumKind, protoreflect.Int32Kind, protoreflect.Sint32Kind,
		protoreflect.Uint32Kind, protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind:
		return protowire.VarintType
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	}
	return protowire.BytesType
}

// strictScan reports the inputs proto.Unmarshal accepts that the rewriter
// must reject. raw has already been accepted by proto.Unmarshal.
func strictScan(raw []byte, md protoreflect.MessageDescriptor, depth int) error {
	if depth > maxWireDepth {
		return errScanDepth
	}
	seen := map[protoreflect.FullName]protowire.Number{}
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		raw = raw[n:]
		m := protowire.ConsumeFieldValue(num, typ, raw)
		val := raw[:m]
		raw = raw[m:]
		fd := md.Fields().ByNumber(num)
		if fd == nil {
			continue
		}
		want := wantWireType(fd)
		packed := fd.IsList() && want != protowire.BytesType && typ == protowire.BytesType
		if typ != want && !packed {
			if md.IsMapEntry() {
				continue // skipped, as proto.Unmarshal skips it
			}
			return errScanType
		}
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() && !md.IsMapEntry() {
			if prev, ok := seen[od.FullName()]; ok && prev != num {
				return errScanOneof
			}
			seen[od.FullName()] = num
		}
		if fd.Kind() == protoreflect.MessageKind {
			v, _ := protowire.ConsumeBytes(val)
			if err := strictScan(v, fd.Message(), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func rootDesc() protoreflect.MessageDescriptor {
	return (&tetragonpb.GetEventsResponse{}).ProtoReflect().Descriptor()
}

// checkRewrite is the differential check: the rewriter and decode ->
// Redact agree on what to reject, and on everything else the rewrite
// decodes to the redacted event.
func checkRewrite(t *testing.T, rw *wireRewriter, red *Redactor, raw []byte) {
	t.Helper()
	out, meta, errW := rw.rewrite(nil, raw)
	ev := &tetragonpb.GetEventsResponse{}
	errO := proto.Unmarshal(raw, ev)
	if errO == nil {
		errO = strictScan(raw, rootDesc(), 1)
	}
	switch {
	case errW != nil && errO != nil:
		return
	case errW != nil:
		t.Fatalf("rewriter rejects (%v) what decode accepts: %x", errW, raw)
	case errO != nil:
		t.Fatalf("rewriter accepts what decode rejects (%v): %x", errO, raw)
	}
	unknown := red.Redact(ev)
	got := &tetragonpb.GetEventsResponse{}
	if err := proto.Unmarshal(out, got); err != nil {
		t.Fatalf("rewrite output does not decode: %v", err)
	}
	if !proto.Equal(got, ev) {
		t.Fatalf("rewrite differs from decode -> redact -> marshal\n got: %v\nwant: %v", got, ev)
	}
	if meta.unknown < unknown {
		t.Fatalf("rewriter counted %d messages with unknown fields, Redact %d", meta.unknown, unknown)
	}
	var event protowire.Number
	if e := ev.ProtoReflect().WhichOneof(rootDesc().Oneofs().ByName("event")); e != nil {
		event = e.Number()
	}
	if meta.event != event {
		t.Fatalf("meta event field %d, decoded %d", meta.event, event)
	}
	if ts := ev.GetTime(); (ts != nil) != meta.hasTime || ts.GetSeconds() != meta.timeSec || ts.GetNanos() != meta.timeNanos {
		t.Fatalf("meta time %v %d.%d, decoded %v", meta.hasTime, meta.timeSec, meta.timeNanos, ts)
	}
}

func testRewriter(t testing.TB, extra ...string) (*wireRewriter, *Redactor) {
	red, err := NewRedactor(extra)
	if err != nil {
		t.Fatal(err)
	}
	rw, err := newWireRewriter(red)
	if err != nil {
		t.Fatal(err)
	}
	return rw, red
}

// TestWirePlan_CoversTheGeneratedRedactor: the plan built from the
// vendored descriptors covers exactly the messages redactgen generated
// code for, plus tetragon.EnvVar: environment_variables is removed, but
// validated first, as proto.Unmarshal would (map entries aside).
func TestWirePlan_CoversTheGeneratedRedactor(t *testing.T) {
	b := wirePlanBuilder{}
	if _, err := b.message(rootDesc()); err != nil {
		t.Fatal(err)
	}
	var got []protoreflect.FullName
	for n, p := range b {
		if !p.mapEntry {
			got = append(got, n)
		}
	}
	slices.Sort(got)
	want := append(redactgen.Messages(), "tetragon.EnvVar")
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("plan messages\n%v\nredactgen messages\n%v", got, want)
	}
}

func TestWire_MatchesRedactOnFilledEvents(t *testing.T) {
	rw, red := testRewriter(t, `hunter\d`, `s3cr[e]t`, `(a|b)c`, `\d{6}`)
	r := rand.New(rand.NewPCG(5, 6)) //nolint:gosec // G404: deterministic test input
	for i := 0; i < 4000; i++ {
		ev := &tetragonpb.GetEventsResponse{}
		fill(ev.ProtoReflect(), r, 0)
		raw, err := proto.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		checkRewrite(t, rw, red, raw)
		out, _, _ := rw.rewrite(nil, raw)
		if strings.Contains(string(out), "unknown-field") {
			t.Fatalf("event %d: a secret survived the rewrite", i)
		}
	}
	for _, raw := range benchCorpus(64) {
		checkRewrite(t, rw, red, raw)
	}
}

func TestWire_Rejections(t *testing.T) {
	rw, _ := testRewriter(t)
	kp := mustMarshal(t, kprobe("/etc/passwd"))
	ex := mustMarshal(t, exec("/bin/true", "x"))
	tag := func(n protowire.Number, typ protowire.Type) []byte { return protowire.AppendTag(nil, n, typ) }
	for name, c := range map[string]struct {
		raw  []byte
		want error
	}{
		"truncated":             {kp[:len(kp)-1], errWireMalformed},
		"bad varint":            {append(tag(fieldTime, protowire.BytesType), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), errWireMalformed},
		"length past end":       {append(tag(fieldProcessExec, protowire.BytesType), 0x7f, 0x00), errWireMalformed},
		"field number zero":     {[]byte{0x02, 0x00}, errWireMalformed},
		"field number over max": {protowire.AppendVarint(nil, uint64(protowire.MaxValidNumber+1)<<3|uint64(protowire.BytesType)), errWireMalformed},
		"wrong wire type":       {protowire.AppendVarint(tag(fieldProcessKprobe, protowire.VarintType), 1), errWireType},
		"string as varint":      {protowire.AppendVarint(tag(1000, protowire.VarintType), 1), errWireType}, // node_name
		"two oneof cases":       {append(append([]byte{}, ex...), kp...), errWireOneof},
		"bad utf-8":             {protowire.AppendBytes(tag(1000, protowire.BytesType), []byte{0xff, 0xfe}), errWireUTF8},
		"bad utf-8 in env": {protowire.AppendBytes(tag(fieldProcessExec, protowire.BytesType),
			protowire.AppendBytes(tag(1, protowire.BytesType), // process
				protowire.AppendBytes(tag(21, protowire.BytesType), // environment_variables
					protowire.AppendBytes(tag(1, protowire.BytesType), []byte{0xc3})))), errWireUTF8},
	} {
		if _, _, err := rw.rewrite(nil, c.raw); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestWire_DepthBound(t *testing.T) {
	// A synthetic plan whose message contains itself: the bound, not the
	// API's shape, stops the recursion.
	p := &wirePlan{name: "self"}
	p.dense = []wirePlanField{{}, {op: opMessage, msg: p, oneof: -1}}
	st := wireState{r: &Redactor{}}
	var raw []byte
	for i := 0; i < maxWireDepth-1; i++ {
		raw = protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), raw)
	}
	if _, err := st.message(nil, raw, p, 1); err != nil {
		t.Fatalf("depth %d rejected: %v", maxWireDepth, err)
	}
	raw = protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), raw)
	if _, err := st.message(nil, raw, p, 1); !errors.Is(err, errWireDepth) {
		t.Fatalf("depth %d: %v", maxWireDepth+1, err)
	}
}

func TestWire_LongNestedMessagesKeepTheirLengths(t *testing.T) {
	rw, red := testRewriter(t)
	long := strings.Repeat("x", 70000)
	ev := exec("/home/a/.ssh/"+long, "--password hunter2 "+long)
	ev.Time = timestamppb.New(timestamppb.Now().AsTime())
	checkRewrite(t, rw, red, mustMarshal(t, ev))
}

func TestWire_MapEntriesAreLenientLikeUnmarshal(t *testing.T) {
	rw, red := testRewriter(t)
	tag := func(n protowire.Number, typ protowire.Type) []byte { return protowire.AppendTag(nil, n, typ) }
	// node_labels (GetEventsResponse field 1004? find it by name) entry
	// with a varint "value" and an unknown field: both skipped.
	fd := rootDesc().Fields().ByName("node_labels")
	entry := protowire.AppendBytes(tag(1, protowire.BytesType), []byte("k"))
	entry = protowire.AppendVarint(append(entry, tag(2, protowire.VarintType)...), 7)
	entry = protowire.AppendVarint(append(entry, tag(9, protowire.VarintType)...), 7)
	raw := protowire.AppendBytes(tag(fd.Number(), protowire.BytesType), entry)
	checkRewrite(t, rw, red, raw)
	// A path in a map value is redacted; the key is kept.
	entry = protowire.AppendBytes(tag(1, protowire.BytesType), []byte("/home/a/.ssh/k"))
	entry = protowire.AppendBytes(append(entry, tag(2, protowire.BytesType)...), []byte("/home/a/.ssh/v"))
	raw = protowire.AppendBytes(tag(fd.Number(), protowire.BytesType), entry)
	checkRewrite(t, rw, red, raw)
	out, _, _ := rw.rewrite(nil, raw)
	if !strings.Contains(string(out), "/home/a/.ssh/k") || strings.Contains(string(out), "/home/a/.ssh/v") {
		t.Fatalf("map key/value handling: %q", out)
	}
}

func TestWire_PackedScalars(t *testing.T) {
	rw, red := testRewriter(t)
	// Find a repeated numeric field anywhere in the API and check packed,
	// unpacked and malformed packed encodings against decode.
	var path []protoreflect.FieldDescriptor
	var find func(md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) bool
	find = func(md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) bool {
		if seen[md.FullName()] {
			return false
		}
		seen[md.FullName()] = true
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if fd.IsList() && wantWireType(fd) == protowire.VarintType {
				path = append(path, fd)
				return true
			}
			if fd.Kind() == protoreflect.MessageKind && !fd.IsMap() && !fd.IsList() && fd.ContainingOneof() == nil {
				path = append(path, fd)
				if find(fd.Message(), seen) {
					return true
				}
				path = path[:len(path)-1]
			}
		}
		return false
	}
	// Search from each event message.
	od := rootDesc().Oneofs().ByName("event")
	for i := 0; i < od.Fields().Len() && path == nil; i++ {
		fd := od.Fields().Get(i)
		path = []protoreflect.FieldDescriptor{fd}
		if !find(fd.Message(), map[protoreflect.FullName]bool{}) {
			path = nil
		}
	}
	if path == nil {
		t.Skip("no repeated varint field reachable through singular messages")
	}
	wrap := func(leaf []byte) []byte {
		for i := len(path) - 2; i >= 0; i-- {
			leaf = protowire.AppendBytes(protowire.AppendTag(nil, path[i].Number(), protowire.BytesType), leaf)
		}
		return leaf
	}
	last := path[len(path)-1].Number()
	packed := protowire.AppendBytes(protowire.AppendTag(nil, last, protowire.BytesType), []byte{1, 2, 0x80, 1})
	unpacked := protowire.AppendVarint(protowire.AppendTag(nil, last, protowire.VarintType), 300)
	bad := protowire.AppendBytes(protowire.AppendTag(nil, last, protowire.BytesType), []byte{0x80})
	for _, leaf := range [][]byte{packed, unpacked, bad, append(append([]byte{}, packed...), unpacked...)} {
		checkRewrite(t, rw, red, wrap(leaf))
	}
}

// FuzzWireRedact is step 7b D1's differential fuzz target: for every
// input, the rewriter and decode -> Redact -> marshal (proto.Equal) agree,
// and when one rejects, so does the other (the oracle's extra rejections
// are strictScan's, which walks the descriptors itself).
func FuzzWireRedact(f *testing.F) {
	r := rand.New(rand.NewPCG(7, 8)) //nolint:gosec // G404: deterministic seeds
	for i := 0; i < 16; i++ {
		ev := &tetragonpb.GetEventsResponse{}
		fill(ev.ProtoReflect(), r, 0)
		raw, _ := proto.Marshal(ev)
		f.Add(raw)
	}
	for _, b := range benchCorpus(8) {
		f.Add(b)
	}
	rw, red := testRewriter(f, `hunter\d`, `(?i)secret`)
	f.Fuzz(func(t *testing.T, raw []byte) {
		checkRewrite(t, rw, red, raw)
	})
}
