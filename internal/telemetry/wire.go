package telemetry

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// Wire-level redaction (step 7b D1, ADR 0039 amended). The pipeline no
// longer decodes each GetEventsResponse, redacts it and marshals it again:
// it rewrites Tetragon's bytes in one pass, keeping every field as sent
// except those redaction changes or removes. The result decodes to exactly
// what decode -> Redact -> marshal produces (FuzzWireRedact checks this
// against the generated redactor, proto.Equal).
//
// The rewriter parses untrusted bytes, so it is held to parser rules:
//   - anything proto.Unmarshal rejects is rejected (bad varint or tag,
//     length past the end, field number out of range, invalid UTF-8 in a
//     string field, a malformed packed field);
//   - it also rejects, where proto.Unmarshal would accept:
//     a known field with the wrong wire type (proto.Unmarshal would keep it
//     as an unknown field), messages nested deeper than maxWireDepth,
//     and two different fields of one oneof in a message (proto.Unmarshal
//     keeps the last; Tetragon never sends both);
//   - unknown fields are dropped and counted, as Redact does. Inside a map
//     entry, unknown or mistyped fields are skipped exactly as
//     proto.Unmarshal skips them.
//
// The per-message plan is built once, at startup, from the vendored v1.8.0
// descriptors, with the generator's rules (internal/redactgen):
// environment_variables removed, a singular string named arguments gets
// the argv rules, every other string (repeated, map value) the ~/.ssh path
// rule, map keys are left as they are.

// maxWireDepth bounds message nesting (GetEventsResponse is depth 1; a map
// entry counts as a level). Tetragon v1.8.0's deepest event is well under
// 10 levels.
const maxWireDepth = 32

// Rewrite errors. Every one is a rejected event, counted as malformed.
var (
	errWireMalformed = errors.New("telemetry: malformed event")
	errWireType      = errors.New("telemetry: event field has the wrong wire type")
	errWireDepth     = errors.New("telemetry: event nested too deeply")
	errWireOneof     = errors.New("telemetry: event sets two fields of one oneof")
	errWireUTF8      = errors.New("telemetry: event string is not UTF-8")
)

type wireOp uint8

const (
	opUnknown wireOp = iota
	opDrop           // environment_variables: validated, removed
	opVarint
	opFixed32
	opFixed64
	opBytes  // bytes: copied
	opString // string: validated, copied (map keys)
	opPath   // string: ~/.ssh path rule
	opArgv   // string: argv rules
	opMessage
)

type wirePlanField struct {
	op    wireOp
	list  bool // repeated: scalars may also come packed
	oneof int8 // index of the (non-synthetic) oneof, or -1
	msg   *wirePlan
}

type wirePlan struct {
	name     protoreflect.FullName
	mapEntry bool
	oneofs   int
	dense    []wirePlanField // by field number; op opUnknown = not a field
	sparse   map[protowire.Number]wirePlanField
}

const wireDenseMax = 256

func (p *wirePlan) field(n protowire.Number) wirePlanField {
	if int(n) < len(p.dense) {
		return p.dense[n]
	}
	return p.sparse[n]
}

// maxWireOneofs bounds the oneofs of one message (Tetragon's messages have
// at most one or two).
const maxWireOneofs = 8

type wirePlanBuilder map[protoreflect.FullName]*wirePlan

func (b wirePlanBuilder) message(md protoreflect.MessageDescriptor) (*wirePlan, error) {
	if p := b[md.FullName()]; p != nil {
		return p, nil
	}
	if md.ParentFile().Syntax() != protoreflect.Proto3 {
		return nil, fmt.Errorf("telemetry: wire plan: %s is not proto3", md.FullName())
	}
	p := &wirePlan{name: md.FullName(), mapEntry: md.IsMapEntry(), sparse: map[protowire.Number]wirePlanField{}}
	b[md.FullName()] = p
	oneofIdx := map[protoreflect.FullName]int8{}
	for i := 0; i < md.Oneofs().Len(); i++ {
		if od := md.Oneofs().Get(i); !od.IsSynthetic() {
			oneofIdx[od.FullName()] = int8(len(oneofIdx)) //nolint:gosec // G115: bounded by maxWireOneofs below
		}
	}
	if len(oneofIdx) > maxWireOneofs {
		return nil, fmt.Errorf("telemetry: wire plan: %s has %d oneofs", md.FullName(), len(oneofIdx))
	}
	p.oneofs = len(oneofIdx)
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		f, err := b.field(fd, p.mapEntry)
		if err != nil {
			return nil, err
		}
		f.oneof = -1
		if od := fd.ContainingOneof(); od != nil && !od.IsSynthetic() {
			f.oneof = oneofIdx[od.FullName()]
		}
		if fd.Number() < wireDenseMax {
			for len(p.dense) <= int(fd.Number()) {
				p.dense = append(p.dense, wirePlanField{})
			}
			p.dense[fd.Number()] = f
		} else {
			p.sparse[fd.Number()] = f
		}
	}
	return p, nil
}

func (b wirePlanBuilder) field(fd protoreflect.FieldDescriptor, inEntry bool) (wirePlanField, error) {
	if fd.Name() == "environment_variables" && !inEntry {
		msg, err := b.message(fd.Message())
		return wirePlanField{op: opDrop, list: fd.IsList(), msg: msg}, err
	}
	f := wirePlanField{list: fd.IsList()}
	switch fd.Kind() {
	case protoreflect.BoolKind, protoreflect.EnumKind, protoreflect.Int32Kind, protoreflect.Sint32Kind,
		protoreflect.Uint32Kind, protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind:
		f.op = opVarint
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		f.op = opFixed32
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		f.op = opFixed64
	case protoreflect.BytesKind:
		f.op = opBytes
	case protoreflect.StringKind:
		switch {
		case inEntry && fd.Number() == 1:
			f.op = opString
		case !inEntry && !fd.IsList() && fd.Name() == "arguments":
			f.op = opArgv
		default:
			f.op = opPath
		}
	case protoreflect.MessageKind:
		msg, err := b.message(fd.Message())
		if err != nil {
			return f, err
		}
		f.op, f.msg = opMessage, msg
	case protoreflect.GroupKind:
		return f, fmt.Errorf("telemetry: wire plan: group field %s", fd.FullName())
	}
	return f, nil
}

// wireRewriter rewrites GetEventsResponse bytes. Immutable after
// newWireRewriter and safe for concurrent use.
type wireRewriter struct {
	root *wirePlan
	r    *Redactor
}

func newWireRewriter(r *Redactor) (*wireRewriter, error) {
	root, err := wirePlanBuilder{}.message((&tetragonpb.GetEventsResponse{}).ProtoReflect().Descriptor())
	if err != nil {
		return nil, err
	}
	return &wireRewriter{root: root, r: r}, nil
}

// wireMeta is what the builder needs from an event, read during the
// rewrite: which event field it carries, and its time.
type wireMeta struct {
	event        protowire.Number // the event oneof's field, 0 if none
	timeSec      int64
	timeNanos    int32
	hasTime      bool
	unknown      int // messages from which unknown fields were dropped
	rateLimitRaw []byte
}

// GetEventsResponse's time field (events.pb.go: protobuf "bytes,1001").
const fieldTime = 1001

type wireState struct {
	r       *Redactor
	discard []byte
	meta    wireMeta
}

// rewrite appends src's redacted form to dst.
func (w *wireRewriter) rewrite(dst, src []byte) ([]byte, wireMeta, error) {
	st := wireState{r: w.r}
	out, err := st.message(dst, src, w.root, 1)
	if err != nil {
		return dst, wireMeta{}, err
	}
	return out, st.meta, nil
}

func (st *wireState) message(dst, src []byte, p *wirePlan, depth int) ([]byte, error) {
	if depth > maxWireDepth {
		return dst, errWireDepth
	}
	var oneofs [maxWireOneofs]protowire.Number
	unknown := false
	for len(src) > 0 {
		num, typ, n := protowire.ConsumeTag(src)
		if n < 0 || num > protowire.MaxValidNumber {
			return dst, errWireMalformed
		}
		tag := src[:n]
		src = src[n:]
		f := p.field(num)
		if f.op == opUnknown || (p.mapEntry && !entryTypeOK(f, typ)) {
			m := protowire.ConsumeFieldValue(num, typ, src)
			if m < 0 {
				return dst, errWireMalformed
			}
			src = src[m:]
			unknown = true
			continue
		}
		if f.oneof >= 0 {
			if prev := oneofs[f.oneof]; prev != 0 && prev != num {
				return dst, errWireOneof
			}
			oneofs[f.oneof] = num
			if depth == 1 {
				st.meta.event = num
			}
		}
		var m int
		var err error
		dst, m, err = st.field(dst, tag, src, f, num, typ, depth)
		if err != nil {
			return dst, err
		}
		src = src[m:]
	}
	if unknown {
		st.meta.unknown++
	}
	return dst, nil
}

// entryTypeOK: inside a map entry, a field with an unexpected wire type is
// skipped like an unknown one (proto.Unmarshal's consumeMap does that).
func entryTypeOK(f wirePlanField, typ protowire.Type) bool {
	switch f.op {
	case opVarint:
		return typ == protowire.VarintType
	case opFixed32:
		return typ == protowire.Fixed32Type
	case opFixed64:
		return typ == protowire.Fixed64Type
	case opUnknown, opDrop, opBytes, opString, opPath, opArgv, opMessage:
		return typ == protowire.BytesType
	}
	return false
}

// field handles one known field whose tag is tag and whose value starts
// src, returning dst with the field's output appended and the value's
// length in src.
func (st *wireState) field(dst, tag, src []byte, f wirePlanField, num protowire.Number, typ protowire.Type, depth int) ([]byte, int, error) {
	if typ == protowire.BytesType {
		v, m := protowire.ConsumeBytes(src)
		if m < 0 {
			return dst, 0, errWireMalformed
		}
		out, err := st.bytesField(dst, tag, v, f, num, depth)
		return out, m, err
	}
	var m int
	switch {
	case f.op == opVarint && typ == protowire.VarintType:
		_, m = protowire.ConsumeVarint(src)
	case f.op == opFixed32 && typ == protowire.Fixed32Type:
		_, m = protowire.ConsumeFixed32(src)
	case f.op == opFixed64 && typ == protowire.Fixed64Type:
		_, m = protowire.ConsumeFixed64(src)
	default:
		return dst, 0, errWireType
	}
	if m < 0 {
		return dst, 0, errWireMalformed
	}
	dst = append(dst, tag...)
	return append(dst, src[:m]...), m, nil
}

// bytesField handles a length-delimited value v.
func (st *wireState) bytesField(dst, tag, v []byte, f wirePlanField, num protowire.Number, depth int) ([]byte, error) {
	switch f.op {
	case opVarint, opFixed32, opFixed64:
		if !f.list || !packedOK(f.op, v) {
			if !f.list {
				return dst, errWireType
			}
			return dst, errWireMalformed
		}
		return appendLenField(dst, tag, v), nil
	case opBytes:
		return appendLenField(dst, tag, v), nil
	case opString, opPath, opArgv:
		if !utf8.Valid(v) {
			return dst, errWireUTF8
		}
		switch {
		case f.op == opPath && bytes.HasPrefix(v, []byte(sshPrefix)):
			if s := st.r.path(string(v)); s != string(v) {
				return appendLenField(dst, tag, []byte(s)), nil
			}
		case f.op == opArgv:
			if s := st.r.argv(string(v)); s != string(v) {
				return appendLenField(dst, tag, []byte(s)), nil
			}
		}
		return appendLenField(dst, tag, v), nil
	case opDrop:
		// Validated as proto.Unmarshal would, then left out.
		var err error
		st.discard, err = st.message(st.discard[:0], v, f.msg, depth+1)
		return dst, err
	case opMessage:
		if depth == 1 {
			switch num { //nolint:exhaustive // two field numbers, not an enum
			case fieldTime:
				st.timestamp(v)
			case fieldRateLimitInfo:
				st.meta.rateLimitRaw = v
			}
		}
		dst = append(dst, tag...)
		start := len(dst)
		dst = append(dst, 0) // one byte reserved for the length
		var err error
		dst, err = st.message(dst, v, f.msg, depth+1)
		if err != nil {
			return dst, err
		}
		return fixLength(dst, start), nil
	case opUnknown:
	}
	return dst, errWireType
}

// timestamp merges a top-level time field into meta (proto merge rules:
// each field present overrides). The message was validated by the rewrite.
func (st *wireState) timestamp(v []byte) {
	st.meta.hasTime = true
	for len(v) > 0 {
		num, typ, n := protowire.ConsumeTag(v)
		if n < 0 {
			return
		}
		v = v[n:]
		if typ == protowire.VarintType && (num == 1 || num == 2) {
			x, m := protowire.ConsumeVarint(v)
			if m < 0 {
				return
			}
			if num == 1 {
				st.meta.timeSec = int64(x) //nolint:gosec // G115: int64 field, two's complement as proto decodes it
			} else {
				st.meta.timeNanos = int32(x) //nolint:gosec // G115: int32 field, truncated as proto decodes it
			}
			v = v[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, v)
		if m < 0 {
			return
		}
		v = v[m:]
	}
}

func appendLenField(dst, tag, v []byte) []byte {
	dst = append(dst, tag...)
	dst = protowire.AppendVarint(dst, uint64(len(v)))
	return append(dst, v...)
}

// fixLength writes the length of dst[start+1:] into the byte reserved at
// dst[start], moving the content up when the length needs more than one
// byte.
func fixLength(dst []byte, start int) []byte {
	n := len(dst) - start - 1
	k := protowire.SizeVarint(uint64(n))
	if k > 1 {
		dst = append(dst, make([]byte, k-1)...)
		copy(dst[start+k:], dst[start+1:start+1+n])
	}
	protowire.AppendVarint(dst[start:start], uint64(n))
	return dst
}

// packedOK checks a packed repeated scalar's contents.
func packedOK(op wireOp, v []byte) bool {
	switch op {
	case opVarint:
		for len(v) > 0 {
			_, m := protowire.ConsumeVarint(v)
			if m < 0 {
				return false
			}
			v = v[m:]
		}
		return true
	case opFixed32:
		return len(v)%4 == 0
	case opFixed64:
		return len(v)%8 == 0
	case opUnknown, opDrop, opBytes, opString, opPath, opArgv, opMessage:
	}
	return false
}
