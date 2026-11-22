package policydoc

import (
	"errors"
	"strings"
	"testing"
)

const validPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    selectors:
      - matchBinaries:
        - operator: "In"
          values:
          - "/usr/bin/sample-exec"
        matchActions:
        - action: "Post"
`

func mustParse(t *testing.T, y string) *Doc {
	t.Helper()
	d, err := Parse("sample", y)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return d
}

func TestParse_Valid(t *testing.T) {
	d := mustParse(t, validPolicy)
	if d.Name() != "sample" {
		t.Fatalf("Name() = %q", d.Name())
	}
}

func TestParse_B1_StructuralRejections(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want error
	}{
		{"empty", "", ErrEmptyYAMLDocument},
		{"whitespace_only", "   \n  \n", ErrEmptyYAMLDocument},
		{"multiple_documents", validPolicy + "\n---\n" + validPolicy, ErrMultipleYAMLDocuments},
		{"anchor", "apiVersion: &a cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec: {}\n", ErrYAMLAnchor},
		{"alias", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: &n x\nspec:\n  kprobes:\n  - call: *n\n", ErrYAMLAnchor},
		{"merge_key", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec:\n  <<: {a: b}\n", ErrYAMLMergeKey},
		{"explicit_tag", "apiVersion: !!str cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec: {}\n", ErrYAMLExplicitTag},
		{"non_string_key", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec:\n  5: y\n", ErrYAMLNonStringKey},
		{"duplicate_key", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nkind: TracingPolicy\nmetadata:\n  name: x\nspec: {}\n", ErrYAMLDuplicateKey},
		{"duplicate_key_unicode_fold", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\n  Name: y\nspec: {}\n", ErrYAMLDuplicateKey},
		{"nul_byte", "apiVersion: cilium.io/v1alpha1\x00\nkind: TracingPolicy\n", ErrYAMLNULByte},
		{"byte_order_mark", "\xEF\xBB\xBFapiVersion: cilium.io/v1alpha1\n", ErrYAMLByteOrderMark},
		{"invalid_utf8", "apiVersion: cilium.io/v1alpha1\n\xFF\xFE", ErrYAMLInvalidUTF8},
		{"control_char", "apiVersion: cilium.io/v1alpha1\x01\nkind: TracingPolicy\n", ErrYAMLControlChar},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("x", tc.yaml)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse(%q) error = %v, want %v", tc.name, err, tc.want)
			}
		})
	}
}

func TestParse_B1_YAML11AmbiguousScalars(t *testing.T) {
	// A bare-word action selector operator is not the right field to
	// abuse here (operator is schema-enum-constrained); use a
	// matchBinaries value, which is schema-typed as a free string, so an
	// ambiguous unquoted scalar reaches the YAML-1.1 check instead of
	// being rejected earlier for an unrelated reason.
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
        - %s
`
	ambiguous := []string{"yes", "Yes", "NO", "on", "Off", "y", "n", "0755", "1:30", ".inf", ".nan"}
	for _, v := range ambiguous {
		t.Run(v, func(t *testing.T) {
			_, err := Parse("sample", strings.ReplaceAll(tmpl, "%s", v))
			if !errors.Is(err, ErrYAMLAmbiguousScalar) {
				t.Fatalf("value %q: error = %v, want ErrYAMLAmbiguousScalar", v, err)
			}
		})
	}
}

func TestParse_B1_QuotedAmbiguousScalarsAccepted(t *testing.T) {
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
        - "yes"
`
	if _, err := Parse("sample", tmpl); err != nil {
		t.Fatalf("quoted ambiguous scalar rejected: %v", err)
	}
}

func TestParse_B1_DepthAndSizeLimits(t *testing.T) {
	deep := "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec:\n"
	indent := "  "
	nest := "a:\n"
	for i := 0; i < 40; i++ {
		deep += strings.Repeat(indent, i+2) + nest
	}
	if _, err := Parse("x", deep); !errors.Is(err, ErrYAMLMaxDepth) {
		t.Fatalf("deep nesting: error = %v, want ErrYAMLMaxDepth", err)
	}

	bigScalar := "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: \"" + strings.Repeat("a", 5000) + "\"\nspec: {}\n"
	if _, err := Parse("x", bigScalar); !errors.Is(err, ErrYAMLScalarTooLarge) {
		t.Fatalf("big scalar: error = %v, want ErrYAMLScalarTooLarge", err)
	}
}

func TestParse_B3_SchemaRejectsWrongType(t *testing.T) {
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes: "not-a-list"
`
	if _, err := Parse("sample", y); !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("error = %v, want ErrSchemaValidation", err)
	}
}

func TestParse_B3_SchemaRejectsUnknownField(t *testing.T) {
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  totallyUnknownField: true
`
	if _, err := Parse("sample", y); !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("error = %v, want ErrSchemaValidation", err)
	}
}

func TestParse_B4_Allowlist(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want error
	}{
		{"wrong_api_version", "apiVersion: v1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec: {}\n", ErrUnsupportedAPIVersion},
		{"namespaced_kind", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicyNamespaced\nmetadata:\n  name: x\nspec: {}\n", ErrUnsupportedKind},
		{"pod_selector", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec:\n  podSelector: {}\n", ErrKubernetesSelector},
		{"container_selector", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec:\n  containerSelector: {}\n", ErrKubernetesSelector},
		{"node_selector", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec:\n  nodeSelector: {}\n", ErrKubernetesSelector},
		{"loader_true", "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\nspec:\n  loader: true\n", ErrUnsupportedHookType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("x", tc.yaml)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParse_B8_NameBinding(t *testing.T) {
	if _, err := Parse("other-name", validPolicy); !errors.Is(err, ErrNameMismatch) {
		t.Fatalf("error = %v, want ErrNameMismatch", err)
	}
	noName := strings.Replace(validPolicy, `name: "sample"`, `name: ""`, 1)
	if _, err := Parse("sample", noName); err == nil {
		t.Fatalf("empty name accepted")
	}
}

func TestParse_MatchWorkloadsRejectedByModel(t *testing.T) {
	// matchWorkloads embeds pod/container/host selectors; the schema
	// allows the field (it is not excluded at B4's top level), so it
	// must still be visible to a reviewer even though no guard rule in
	// this step currently inspects it (see docs/reports/step-02b.md open
	// questions). This test documents current behavior: it decodes, but
	// is intentionally retained in the typed model as a signal.
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "x"
    selectors:
    - matchWorkloads:
        podSelector: {}
`
	if _, err := Parse("sample", y); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParse_UnknownMacro(t *testing.T) {
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "x"
    selectors:
    - macros: ["doesnotexist"]
`
	_, err := Parse("sample", y)
	if !errors.Is(err, ErrUnknownMacro) {
		t.Fatalf("error = %v, want ErrUnknownMacro", err)
	}
}

func TestParse_MacroMergesActions(t *testing.T) {
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  selectorsMacros:
    enforce-macro:
      matchActions:
      - action: "Sigkill"
  kprobes:
  - call: "x"
    selectors:
    - macros: ["enforce-macro"]
`
	d, err := Parse("sample", y)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sel := d.Hooks()[0].Selectors[0]
	if len(sel.MatchActions) != 1 || sel.MatchActions[0].Action != "Sigkill" {
		t.Fatalf("macro actions not merged: %+v", sel.MatchActions)
	}
}
