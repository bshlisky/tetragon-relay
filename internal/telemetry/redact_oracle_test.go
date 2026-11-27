package telemetry

import (
	"math/rand/v2"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// oracle is step 7a's reflection walk (the redactor before step 7b P2),
// kept as the reference the generated redactor must match, plus the one
// rule 7b adds: unknown fields are dropped. Its argv rule runs every
// pattern unconditionally (no prefilter).
type oracle struct{ r *Redactor }

func (o oracle) redact(ev *tetragonpb.GetEventsResponse) { o.walk(ev.ProtoReflect()) }

func (o oracle) argv(s string) string {
	for _, p := range o.r.patterns {
		s = p.re.ReplaceAllLiteralString(s, Redacted)
	}
	if !strings.Contains(s, "/home/") {
		return s
	}
	toks := strings.Split(s, " ")
	for i, t := range toks {
		if sshPath.MatchString(t) {
			toks[i] = HashPath(t)
		}
	}
	return strings.Join(toks, " ")
}

func (o oracle) walk(m protoreflect.Message) {
	m.SetUnknown(nil)
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := string(fd.Name())
		if name == "environment_variables" {
			m.Clear(fd)
			return true
		}
		switch {
		case fd.IsMap():
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					o.walk(mv.Message())
					return true
				})
			} else if fd.MapValue().Kind() == protoreflect.StringKind {
				mp := v.Map()
				mp.Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
					if s := mv.String(); sshPath.MatchString(s) {
						mp.Set(k, protoreflect.ValueOfString(HashPath(s)))
					}
					return true
				})
			}
		case fd.IsList():
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				switch fd.Kind() { //nolint:exhaustive // as the 7a walk
				case protoreflect.MessageKind, protoreflect.GroupKind:
					o.walk(l.Get(i).Message())
				case protoreflect.StringKind:
					if s := l.Get(i).String(); sshPath.MatchString(s) {
						l.Set(i, protoreflect.ValueOfString(HashPath(s)))
					}
				}
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			o.walk(v.Message())
		case fd.Kind() == protoreflect.StringKind:
			s := v.String()
			out := s
			if name == "arguments" {
				out = o.argv(s)
			} else if sshPath.MatchString(s) {
				out = HashPath(s)
			}
			if out != s {
				m.Set(fd, protoreflect.ValueOfString(out))
			}
		}
		return true
	})
}

// fillStrings are the values the filler puts in string fields: paths
// inside and outside ~/.ssh, argv secrets, the Kelvin-sign fold case, and
// plain text.
var fillStrings = []string{
	"/home/alice/.ssh/id_ed25519", "/home/bob/.ssh", "/home/bob/.sshx", "/home/carol/src/.ssh/x", "/root/.ssh/id_rsa",
	"--password hunter2 -v", "-H token=abc123 /home/alice/.ssh/known_hosts", "AKIAABCDEFGHIJKLMNOP x",
	"TO\u212aEN=kelvin", "to\u212aen=kelvin", "--pa\u017f\u017fword s3cret", "plain", "", "/usr/bin/curl",
	"ssh -i /home/dave/.ssh/key host", "--PASSWORD=Upper",
}

// fill sets every field of m (one oneof case each call, chosen at random),
// to depth 6, and sometimes unknown fields.
func fill(m protoreflect.Message, r *rand.Rand, depth int) {
	if depth > 6 {
		return
	}
	md := m.Descriptor()
	str := func() string { return fillStrings[r.IntN(len(fillStrings))] }
	fields := md.Fields()
	chosen := map[protoreflect.FullName]protoreflect.FieldDescriptor{}
	for i := 0; i < md.Oneofs().Len(); i++ {
		od := md.Oneofs().Get(i)
		chosen[od.FullName()] = od.Fields().Get(r.IntN(od.Fields().Len()))
	}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if od := fd.ContainingOneof(); od != nil && chosen[od.FullName()] != fd {
			continue
		}
		switch {
		case fd.IsMap():
			mp := m.Mutable(fd).Map()
			for j := 0; j < 1+r.IntN(2); j++ {
				var k protoreflect.MapKey
				switch fd.MapKey().Kind() { //nolint:exhaustive // the API's map keys
				case protoreflect.StringKind:
					k = protoreflect.ValueOfString(str() + string(rune('a'+j))).MapKey()
				default:
					k = protoreflect.ValueOfUint32(uint32(j)).MapKey() //nolint:gosec // G115: tiny
				}
				switch fd.MapValue().Kind() { //nolint:exhaustive // the API's map values
				case protoreflect.StringKind:
					mp.Set(k, protoreflect.ValueOfString(str()))
				case protoreflect.MessageKind:
					v := mp.NewValue()
					fill(v.Message(), r, depth+1)
					mp.Set(k, v)
				}
			}
		case fd.IsList():
			l := m.Mutable(fd).List()
			for j := 0; j < 1+r.IntN(2); j++ {
				switch fd.Kind() { //nolint:exhaustive // elements the walk handles; others are left empty
				case protoreflect.StringKind:
					l.Append(protoreflect.ValueOfString(str()))
				case protoreflect.MessageKind:
					v := l.NewElement()
					fill(v.Message(), r, depth+1)
					l.Append(v)
				}
			}
		case fd.Kind() == protoreflect.MessageKind:
			v := m.NewField(fd)
			fill(v.Message(), r, depth+1)
			m.Set(fd, v)
		case fd.Kind() == protoreflect.StringKind:
			m.Set(fd, protoreflect.ValueOfString(str()))
		}
	}
	if r.IntN(4) == 0 {
		unk := protowire.AppendTag(nil, 9999, protowire.BytesType)
		m.SetUnknown(protowire.AppendBytes(unk, []byte("SECRET_TOKEN=unknown-field")))
	}
}

func TestRedact_MatchesReflectionWalk(t *testing.T) {
	red, err := NewRedactor([]string{`hunter\d`, `s3cr[e]t`, `(a|b)c`, `\d{6}`})
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: deterministic test input
	for i := 0; i < 4000; i++ {
		ev := &tetragonpb.GetEventsResponse{}
		fill(ev.ProtoReflect(), r, 0)
		want := proto.Clone(ev).(*tetragonpb.GetEventsResponse)
		oracle{red}.redact(want)
		red.Redact(ev)
		if !proto.Equal(ev, want) {
			t.Fatalf("event %d: generated redactor differs from the reflection walk\n got: %v\nwant: %v", i, ev, want)
		}
		if raw, _ := proto.Marshal(ev); strings.Contains(string(raw), "unknown-field") {
			t.Fatalf("event %d: an unknown field survived redaction", i)
		}
	}
}

func TestRedact_UnknownFieldsDroppedAndCounted(t *testing.T) {
	red, _ := NewRedactor(nil)
	ev := exec("/bin/true", "")
	p := ev.GetProcessExec().GetProcess()
	p.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 9999, protowire.BytesType), []byte("SECRET_TOKEN=x")))
	ev.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 9998, protowire.VarintType), 1))
	if n := red.Redact(ev); n != 2 {
		t.Fatalf("Redact reported %d messages with unknown fields, want 2", n)
	}
	if len(p.ProtoReflect().GetUnknown()) != 0 || len(ev.ProtoReflect().GetUnknown()) != 0 {
		t.Fatal("unknown fields kept")
	}
	if n := red.Redact(ev); n != 0 {
		t.Fatalf("second Redact reported %d", n)
	}
}

// The prefilter must never skip a pattern that would match. Under (?i)
// the ASCII letters k and s also match U+212A and U+017F, so non-ASCII
// input always runs the regexp.
func TestRedact_PrefilterFoldCases(t *testing.T) {
	red, _ := NewRedactor(nil)
	for _, in := range []string{"TO\u212aEN=kelvin", "to\u212aen=k", "--pa\u017f\u017fword=x", "--PassWord x", "TOKEN=X", "xAKIAABCDEFGHIJKLMNOPx",
		strings.Repeat("a", prefilterMax) + " TOKEN=long", "token=a " + strings.Repeat("b", prefilterMax)} {
		if got := red.argv(in); !strings.Contains(got, Redacted) {
			t.Errorf("argv(%q) = %q: not redacted", in, got)
		}
		if got, want := red.argv(in), (oracle{red}).argv(in); got != want {
			t.Errorf("argv(%q) = %q, oracle %q", in, got, want)
		}
	}
	for _, c := range []struct {
		pattern string
		want    []string
	}{
		{`(?i)--password[= ]\S+`, []string{"--password"}},
		{`AKIA[0-9A-Z]{16}`, []string{"akia"}},
		{`(foo)bar\d`, []string{"foo", "bar"}},
		{`foo|bar`, nil},
		{`\d{6}`, nil},
		{`(?i)caf\x{e9}`, nil},
		{`(`, nil},
	} {
		var got []string
		for _, l := range requiredLiterals(c.pattern) {
			got = append(got, string(l))
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("requiredLiterals(%q) = %q, want %q", c.pattern, got, c.want)
		}
	}
}

func FuzzRedactEquivalence(f *testing.F) {
	r := rand.New(rand.NewPCG(3, 4)) //nolint:gosec // G404: deterministic seeds
	for i := 0; i < 16; i++ {
		ev := &tetragonpb.GetEventsResponse{}
		fill(ev.ProtoReflect(), r, 0)
		raw, _ := proto.Marshal(ev)
		f.Add(raw)
	}
	for _, b := range benchCorpus(8) {
		f.Add(b)
	}
	red, _ := NewRedactor([]string{`hunter\d`, `(?i)secret`})
	f.Fuzz(func(t *testing.T, raw []byte) {
		ev := &tetragonpb.GetEventsResponse{}
		if proto.Unmarshal(raw, ev) != nil {
			return
		}
		want := proto.Clone(ev).(*tetragonpb.GetEventsResponse)
		oracle{red}.redact(want)
		red.Redact(ev)
		if !proto.Equal(ev, want) {
			t.Fatalf("generated redactor differs from the reflection walk\n got: %v\nwant: %v", ev, want)
		}
	})
}

func FuzzArgvPrefilter(f *testing.F) {
	for _, s := range fillStrings {
		f.Add(s, `(?i)token=\S+`)
	}
	f.Add("x\u212a", `(?i)xk`)
	f.Add("abcabc", `(abc)+`)
	f.Fuzz(func(t *testing.T, s, pattern string) {
		red, err := NewRedactor([]string{pattern})
		if err != nil {
			return
		}
		if got, want := red.argv(s), (oracle{red}).argv(s); got != want {
			t.Fatalf("pattern %q, input %q: prefiltered %q, unfiltered %q", pattern, s, got, want)
		}
	})
}
