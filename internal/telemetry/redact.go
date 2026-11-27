package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	tetragonpb "github.com/bshlisky/tetragon-relay/third_party/tetragon/v1.8.0/api/v1/tetragon"
)

// DefaultArgvPatterns is the built-in redaction set (architecture doc 8.6's
// example patterns). Config can only add to it (ADR 0039 section 7);
// signed patterns are step 7b.
var DefaultArgvPatterns = []string{
	`(?i)--password[= ]\S+`,
	`(?i)token=\S+`,
	`AKIA[0-9A-Z]{16}`,
}

// Redacted replaces an argv match.
const Redacted = "[REDACTED]"

// sshPath matches /home/<user>/.ssh and anything under it.
var sshPath = regexp.MustCompile(`^/home/[^/]+/\.ssh(/|$)`)

// Redactor applies ADR 0039 section 7's redaction to a GetEventsResponse in
// place, before anything is spooled.
type Redactor struct {
	argv []*regexp.Regexp
}

// NewRedactor compiles DefaultArgvPatterns plus extra (Go RE2 only: no
// backtracking). A pattern that does not compile is an error; config
// validation calls this at startup.
func NewRedactor(extra []string) (*Redactor, error) {
	r := &Redactor{}
	for _, p := range append(append([]string(nil), DefaultArgvPatterns...), extra...) {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("telemetry: redaction pattern %q: %w", p, err)
		}
		r.argv = append(r.argv, re)
	}
	return r, nil
}

// HashPath is the replacement for a path under /home/*/.ssh/.
func HashPath(p string) string {
	sum := sha256.Sum256([]byte(p))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Redact redacts ev in place:
//   - every field named environment_variables is cleared (process, parent
//     and every ancestor);
//   - in every field named arguments, every match of any pattern becomes
//     [REDACTED], and every space-separated token that is a path under
//     /home/*/.ssh becomes sha256:<hex>;
//   - every other string field anywhere in the event (binary, cwd, kprobe,
//     tracepoint, uprobe and LSM path, file and string arguments, ...) that
//     is a path under /home/*/.ssh becomes sha256:<hex>.
//
// It walks the message by reflection, so a field Tetragon adds in a later
// API version is covered by the same rules.
func (r *Redactor) Redact(ev *tetragonpb.GetEventsResponse) {
	r.walk(ev.ProtoReflect())
}

func (r *Redactor) walk(m protoreflect.Message) {
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
					r.walk(mv.Message())
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
				switch fd.Kind() { //nolint:exhaustive // only message and string elements carry paths or argv
				case protoreflect.MessageKind, protoreflect.GroupKind:
					r.walk(l.Get(i).Message())
				case protoreflect.StringKind:
					if s := l.Get(i).String(); sshPath.MatchString(s) {
						l.Set(i, protoreflect.ValueOfString(HashPath(s)))
					}
				}
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			r.walk(v.Message())
		case fd.Kind() == protoreflect.StringKind:
			s := v.String()
			out := s
			if name == "arguments" {
				out = r.redactArgv(s)
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

func (r *Redactor) redactArgv(s string) string {
	for _, re := range r.argv {
		s = re.ReplaceAllLiteralString(s, Redacted)
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
