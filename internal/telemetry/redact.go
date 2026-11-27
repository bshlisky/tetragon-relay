package telemetry

//go:generate go test ./internal/redactgen -run TestRedactGenUpToDate -count=1 -args -update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

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

// sshPrefix is a prefix every sshPath match has.
const sshPrefix = "/home/"

// argvPattern is one compiled pattern and its prefilter: lower-case
// ASCII literals that every match contains (folded to lower case), so an
// ASCII string that lacks one of them cannot match and the regexp is not
// run. lits is empty when the pattern has no such literal; then the
// regexp always runs.
type argvPattern struct {
	re   *regexp.Regexp
	lits [][]byte
}

// Redactor applies ADR 0039 section 7's redaction to a GetEventsResponse in
// place, before anything is spooled. It is immutable after NewRedactor and
// safe for concurrent use.
type Redactor struct {
	patterns []argvPattern
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
		r.patterns = append(r.patterns, argvPattern{re: re, lits: requiredLiterals(p)})
	}
	return r, nil
}

// requiredLiterals returns lower-case ASCII literals that every match of
// pattern contains: the literal pieces of a top-level concatenation
// (inside capture groups too). Each is necessary on its own, so a string
// lacking any one of them cannot match. A pattern with none (an
// alternation, a single class, ...) gets none and is always run. Only
// ASCII literals are used: under (?i), ASCII letters fold to non-ASCII
// runes (k to U+212A KELVIN SIGN, s to U+017F), which is why the
// prefilter is applied to pure-ASCII input only.
func requiredLiterals(pattern string) [][]byte {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()
	var out [][]byte
	var visit func(r *syntax.Regexp, top bool)
	visit = func(r *syntax.Regexp, top bool) {
		switch r.Op { //nolint:exhaustive // every other op contributes no necessary literal
		case syntax.OpLiteral:
			s := string(r.Rune)
			if s != "" && isASCII(s) {
				out = append(out, []byte(strings.ToLower(s)))
			}
		case syntax.OpCapture:
			visit(r.Sub[0], top)
		case syntax.OpConcat:
			if top {
				for _, sub := range r.Sub {
					visit(sub, false)
				}
			}
		}
	}
	visit(re, true)
	return out
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// lowerASCII appends s lower-cased to dst and reports whether s is pure
// ASCII (if it is not, the result must not be used).
func lowerASCII(dst []byte, s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			return dst, false
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst, true
}

// prefilterMax bounds the stack buffer argv lower-cases into; a longer
// arguments string runs every pattern.
const prefilterMax = 1024

// HashPath is the replacement for a path under /home/*/.ssh/.
func HashPath(p string) string {
	sum := sha256.Sum256([]byte(p))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Redact redacts ev in place and reports how many messages in it carried
// unknown fields (which are dropped):
//   - every field named environment_variables is cleared (process, parent
//     and every ancestor);
//   - in every string field named arguments, every match of any pattern
//     becomes [REDACTED], and every space-separated token that is a path
//     under /home/*/.ssh becomes sha256:<hex>;
//   - every other string field anywhere in the event (binary, cwd, kprobe,
//     tracepoint, uprobe and LSM path, file and string arguments, map
//     values, ...) that is a path under /home/*/.ssh becomes sha256:<hex>;
//   - unknown fields (fields of a newer Tetragon API than the vendored
//     v1.8.0) are removed from every message: they cannot be redacted.
//
// The field-by-field code is generated from the vendored API's descriptors
// (redact_gen.go, internal/redactgen), so every field the API has is
// covered, and TestRedactGenUpToDate fails if the API changes without
// regenerating. TestRedact_MatchesReflectionWalk and FuzzRedactEquivalence
// check it against the reflection walk it replaced.
func (r *Redactor) Redact(ev *tetragonpb.GetEventsResponse) (unknownDropped int) {
	x := redaction{Redactor: r}
	x.redactEvent(ev)
	return x.unknown
}

// redaction is one Redact call's state.
type redaction struct {
	*Redactor
	unknown int
}

func (r *redaction) dropUnknown(m proto.Message) {
	if pm := m.ProtoReflect(); len(pm.GetUnknown()) > 0 {
		pm.SetUnknown(nil)
		r.unknown++
	}
}

// path applies the ~/.ssh rule to one string field.
func (r *Redactor) path(s string) string {
	if !strings.HasPrefix(s, sshPrefix) || !sshPath.MatchString(s) {
		return s
	}
	return HashPath(s)
}

// argv applies the argument rules to an arguments field. A pattern is
// skipped only when s is pure ASCII and, lower-cased, lacks one of the
// pattern's required literals (requiredLiterals): it cannot match then.
func (r *Redactor) argv(s string) string {
	var buf [prefilterMax]byte
	lower, ascii := []byte(nil), false
	if len(s) <= prefilterMax {
		lower, ascii = lowerASCII(buf[:0], s)
	}
	for _, p := range r.patterns {
		if len(p.lits) > 0 && ascii && !containsAll(lower, p.lits) {
			continue
		}
		if out := p.re.ReplaceAllLiteralString(s, Redacted); out != s {
			s = out
			lower, ascii = nil, false
			if len(s) <= prefilterMax {
				lower, ascii = lowerASCII(buf[:0], s)
			}
		}
	}
	if !strings.Contains(s, sshPrefix) {
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

func containsAll(lower []byte, lits [][]byte) bool {
	for _, l := range lits {
		if !bytes.Contains(lower, l) {
			return false
		}
	}
	return true
}
