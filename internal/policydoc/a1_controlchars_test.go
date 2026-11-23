package policydoc

import (
	"errors"
	"fmt"
	"testing"
)

// TestParse_A1_ArchitectProbes reproduces, verbatim, the four probes from
// architect review R2D-1 (docs/reviews/step-02d-review.md) that passed
// Parse + Check before this fix. Each uses a YAML double-quoted scalar's
// escape sequence, never a literal control byte, so checkRawBytes alone
// cannot catch any of them.
func TestParse_A1_ArchitectProbes(t *testing.T) {
	tmpl := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "security_bprm_check"
    selectors:
    - matchBinaries:
      - operator: "%s"
        values:
        - "%s"
      matchActions:
      - action: "Sigkill"
`
	cases := []struct {
		name     string
		operator string
		value    string
		want     error
	}{
		{"prefix_nul_escape", "Prefix", `/\0anything`, ErrYAMLInvisibleOrControlChar},
		{"prefix_tab_escape", "Prefix", `/\tx`, ErrSelectorValueWhitespace},
		{"in_unicode_nul_escape", "In", `/opt/app\u0000/usr/sbin/sshd`, ErrYAMLInvisibleOrControlChar},
		{"prefix_bidi_override_escape", "Prefix", `/\u202e`, ErrYAMLInvisibleOrControlChar},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := fmt.Sprintf(tmpl, tc.operator, tc.value)
			_, err := Parse("sample", y)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse(%s %q) error = %v, want %v", tc.operator, tc.value, err, tc.want)
			}
		})
	}
}

// TestParse_A1_GenericScalarCharacterClasses exercises
// isDisallowedScalarRune's rule set directly through Parse, independent of
// which field the character appears in (metadata.name's sibling fields are
// avoided since the name itself is pattern-constrained; a matchBinaries
// value is schema-typed as a free string).
func TestParse_A1_GenericScalarCharacterClasses(t *testing.T) {
	tmpl := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "x"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "%s"
`
	cases := []struct {
		name  string
		value string
	}{
		// Category Cc other than tab/LF/CR, reached only via escape
		// (U+0085 NEL is a C1 control; written literally it is a
		// 2-byte UTF-8 sequence already caught by checkRawBytes, so
		// this specifically tests the decoded-scalar path).
		{"cc_nel_escape", `a\u0085b`},
		{"cc_c0_escape", `a\u0001b`},
		// Category Cf: zero-width space, zero-width joiner, BOM as a
		// decoded character (not a leading document BOM).
		{"cf_zero_width_space", `a\u200bb`},
		{"cf_zero_width_joiner", `a\u200db`},
		{"cf_bom_mid_string", `a\ufeffb`},
		// Line/paragraph separators.
		{"line_separator", `a\u2028b`},
		{"paragraph_separator", `a\u2029b`},
		// Noncharacters: BMP (U+FFFE) and an astral-plane one
		// (U+1FFFE, via YAML's 8-hex-digit \U escape).
		{"noncharacter_bmp", `a\ufffeb`},
		{"noncharacter_fdd0_block", `a\ufdd5b`},
		{"noncharacter_astral", `a\U0001fffeb`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := fmt.Sprintf(tmpl, tc.value)
			_, err := Parse("sample", y)
			if !errors.Is(err, ErrYAMLInvisibleOrControlChar) {
				t.Fatalf("Parse(%q) error = %v, want ErrYAMLInvisibleOrControlChar", tc.value, err)
			}
		})
	}
}

// TestParse_A1_AllowedEverywhereExceptSensitiveFields documents that
// tab/LF/CR remain legal in an ordinary free-form field (a kprobe
// message), but not in the sensitive fields Part A1 names.
func TestParse_A1_TabAllowedInMessage(t *testing.T) {
	y := "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  kprobes:\n  - call: \"x\"\n    message: \"line one\\tline two\"\n"
	if _, err := Parse("sample", y); err != nil {
		t.Fatalf("tab in message field rejected: %v", err)
	}
}

// TestParse_A1_HookIdentifierWhitespace covers every hook-identifier field
// the prompt names: call, path, symbols, hook. checkIdentifierWhitespace
// (buildHooks, B6/post-schema) is what rejects these.
func TestParse_A1_HookIdentifierWhitespace(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"kprobe_call", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  kprobes:\n  - call: \"sys\\tcall\"\n"},
		{"uprobe_path", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  uprobes:\n  - path: \"/bin/bash\\t\"\n    symbols:\n    - \"readline\"\n"},
		{"uprobe_symbols", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  uprobes:\n  - path: \"/bin/bash\"\n    symbols:\n    - \"read\\nline\"\n"},
		{"lsmhook_hook", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  lsmhooks:\n  - hook: \"file\\t_open\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("sample", tc.yaml)
			if !errors.Is(err, ErrHookIdentifierWhitespace) {
				t.Fatalf("Parse error = %v, want ErrHookIdentifierWhitespace", err)
			}
		})
	}
}

// TestParse_A1_TracepointIdentifierAlreadyBlockedBySchema documents that
// subsystem/event, the other two identifier fields Part A1 names, cannot
// actually carry a tab/LF/CR: the pinned v1.8.0 CRD schema's own pattern
// (`^[a-zA-Z0-9_][a-zA-Z0-9_-]*$`) already excludes them at B3, before
// buildHooks's checkIdentifierWhitespace (B6/post-schema) would run. The
// checkIdentifierWhitespace calls on t.Subsystem/t.Event in buildHooks are
// kept anyway as defense in depth (see docs/reports/step-03.md section 14)
// in case a future schema revision loosens that pattern.
func TestParse_A1_TracepointIdentifierAlreadyBlockedBySchema(t *testing.T) {
	cases := []string{
		"apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  tracepoints:\n  - subsystem: \"sched\\n\"\n    event: \"sched_process_exec\"\n",
		"apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  tracepoints:\n  - subsystem: \"sched\"\n    event: \"sched\\rexec\"\n",
	}
	for _, y := range cases {
		if _, err := Parse("sample", y); !errors.Is(err, ErrSchemaValidation) {
			t.Fatalf("Parse error = %v, want ErrSchemaValidation", err)
		}
	}
}

// TestParse_A1_SelectorValueWhitespace covers matchBinaries,
// matchParentBinaries, matchArgs, and the macro-merge path.
func TestParse_A1_SelectorValueWhitespace(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"matchBinaries", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  kprobes:\n  - call: \"x\"\n    selectors:\n    - matchBinaries:\n      - operator: \"In\"\n        values:\n        - \"/usr/bin/a\\tb\"\n"},
		{"matchParentBinaries", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  kprobes:\n  - call: \"x\"\n    selectors:\n    - matchParentBinaries:\n      - operator: \"In\"\n        values:\n        - \"/usr/bin/a\\nb\"\n"},
		{"matchArgs", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  kprobes:\n  - call: \"x\"\n    selectors:\n    - matchArgs:\n      - index: 0\n        operator: \"Equal\"\n        values:\n        - \"/etc/pass\\rwd\"\n"},
		{"matchReturnArgs", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  kprobes:\n  - call: \"x\"\n    selectors:\n    - matchReturnArgs:\n      - operator: \"Equal\"\n        values:\n        - \"a\\tb\"\n"},
		{
			"via_macro_matchBinaries",
			"apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  selectorsMacros:\n    bad:\n      matchBinaries:\n      - operator: \"In\"\n        values:\n        - \"/usr/bin/a\\tb\"\n  kprobes:\n  - call: \"x\"\n    selectors:\n    - macros:\n      - \"bad\"\n",
		},
		{
			"via_macro_matchArgs",
			"apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  selectorsMacros:\n    bad:\n      matchArgs:\n      - index: 0\n        operator: \"Equal\"\n        values:\n        - \"a\\tb\"\n  kprobes:\n  - call: \"x\"\n    selectors:\n    - macros:\n      - \"bad\"\n",
		},
		{
			"via_macro_matchParentBinaries",
			"apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  selectorsMacros:\n    bad:\n      matchParentBinaries:\n      - operator: \"In\"\n        values:\n        - \"/usr/bin/a\\nb\"\n  kprobes:\n  - call: \"x\"\n    selectors:\n    - macros:\n      - \"bad\"\n",
		},
		{
			"via_macro_matchReturnArgs",
			"apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"sample\"\nspec:\n  selectorsMacros:\n    bad:\n      matchReturnArgs:\n      - operator: \"Equal\"\n        values:\n        - \"a\\rb\"\n  kprobes:\n  - call: \"x\"\n    selectors:\n    - macros:\n      - \"bad\"\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("sample", tc.yaml)
			if !errors.Is(err, ErrSelectorValueWhitespace) {
				t.Fatalf("Parse error = %v, want ErrSelectorValueWhitespace", err)
			}
		})
	}
}
