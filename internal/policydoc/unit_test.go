package policydoc

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestParse_NumberPreservation(t *testing.T) {
	// Decimal literal already valid JSON syntax: preserved byte-for-byte.
	// Hex/underscore literal: re-rendered via exact-precision formatting.
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "x"
    args:
    - index: 0
      type: "int32"
      sizeArgIndex: 0x10
`
	d, err := Parse("sample", y)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(string(d.CanonicalJSON()), `"sizeArgIndex":16`) {
		t.Fatalf("hex literal not re-rendered to decimal: %s", d.CanonicalJSON())
	}
}

func TestParse_FloatAndBoolAndNullScalars(t *testing.T) {
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
  annotations:
    note: null
    ratio: 1.50
    enabled: True
spec: {}
`
	d, err := Parse("sample", y)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	j := string(d.CanonicalJSON())
	for _, want := range []string{`"note":null`, `"ratio":1.50`, `"enabled":true`} {
		if !strings.Contains(j, want) {
			t.Fatalf("canonical JSON missing %q: %s", want, j)
		}
	}
}

func TestParse_B1_TooManyKeysInObject(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: x\n  annotations:\n")
	for i := 0; i < 4100; i++ {
		sb.WriteString("    k")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString(": v\n")
	}
	sb.WriteString("spec: {}\n")
	_, err := Parse("x", sb.String())
	if !errors.Is(err, ErrYAMLTooManyKeys) {
		t.Fatalf("error = %v, want ErrYAMLTooManyKeys", err)
	}
}

func TestCheckActionCompleteness_Mismatch(t *testing.T) {
	generic := map[string]interface{}{
		"spec": map[string]interface{}{
			"hidden": []interface{}{
				map[string]interface{}{
					"matchActions": []interface{}{
						map[string]interface{}{"action": "Sigkill"},
					},
				},
			},
		},
	}
	typed := &rawDoc{} // no kprobes/tracepoints/etc: typed model sees zero actions
	err := checkActionCompleteness(generic, typed)
	if !errors.Is(err, ErrUnmodeledAction) {
		t.Fatalf("error = %v, want ErrUnmodeledAction", err)
	}
}

func TestCheckActionCompleteness_Match(t *testing.T) {
	generic := map[string]interface{}{
		"spec": map[string]interface{}{
			"kprobes": []interface{}{
				map[string]interface{}{
					"selectors": []interface{}{
						map[string]interface{}{
							"matchActions": []interface{}{
								map[string]interface{}{"action": "Post"},
							},
						},
					},
				},
			},
		},
	}
	typed := &rawDoc{
		Spec: rawSpec{
			KProbes: []rawKProbeSpec{{
				Selectors: []rawSelector{{
					MatchActions: []rawActionSelector{{Action: "Post"}},
				}},
			}},
		},
	}
	if err := checkActionCompleteness(generic, typed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractOpenAPIV3Schema_Errors(t *testing.T) {
	cases := []interface{}{
		"not a map",
		map[string]interface{}{},
		map[string]interface{}{"spec": "not a map"},
		map[string]interface{}{"spec": map[string]interface{}{"versions": "not a list"}},
		map[string]interface{}{"spec": map[string]interface{}{"versions": []interface{}{}}},
		map[string]interface{}{"spec": map[string]interface{}{"versions": []interface{}{"not a map"}}},
		map[string]interface{}{"spec": map[string]interface{}{"versions": []interface{}{map[string]interface{}{"name": "v1"}}}},
		map[string]interface{}{"spec": map[string]interface{}{"versions": []interface{}{map[string]interface{}{"name": "v1alpha1"}}}},
		map[string]interface{}{"spec": map[string]interface{}{"versions": []interface{}{map[string]interface{}{"name": "v1alpha1", "schema": "not a map"}}}},
		map[string]interface{}{"spec": map[string]interface{}{"versions": []interface{}{map[string]interface{}{"name": "v1alpha1", "schema": map[string]interface{}{}}}}},
	}
	for i, c := range cases {
		if _, err := extractOpenAPIV3Schema(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestDoc_CanonicalSHA256(t *testing.T) {
	d := mustParse(t, validPolicy)
	sum := d.CanonicalSHA256()
	if sum == ([32]byte{}) {
		t.Fatalf("CanonicalSHA256() is all-zero")
	}
	// Deterministic: parsing the same document twice gives the same digest.
	d2 := mustParse(t, validPolicy)
	if d.CanonicalSHA256() != d2.CanonicalSHA256() {
		t.Fatalf("CanonicalSHA256 not stable across Parse calls")
	}
}

func TestHookKind_String(t *testing.T) {
	cases := map[HookKind]string{
		HookKindKProbe:     "kprobe",
		HookKindTracepoint: "tracepoint",
		HookKindUProbe:     "uprobe",
		HookKindLsmHook:    "lsmhook",
		HookKind(99):       "unknown",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Fatalf("HookKind(%d).String() = %q, want %q", k, got, want)
		}
	}
}

func TestParse_NumberPreservation_UintAndFloatLiterals(t *testing.T) {
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "x"
    args:
    - index: 0
      type: "uint64"
      sizeArgIndex: 1_8
`
	d, err := Parse("sample", y)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(string(d.CanonicalJSON()), `"sizeArgIndex":18`) {
		t.Fatalf("underscore int literal not re-rendered: %s", d.CanonicalJSON())
	}
}

func TestCheckRawBytes_ControlChars(t *testing.T) {
	if err := checkRawBytes([]byte{0x7F}); !errors.Is(err, ErrYAMLControlChar) {
		t.Fatalf("DEL: error = %v, want ErrYAMLControlChar", err)
	}
	if err := checkRawBytes([]byte("a\u0085b")); !errors.Is(err, ErrYAMLControlChar) {
		t.Fatalf("C1 control (NEL): error = %v, want ErrYAMLControlChar", err)
	}
	if err := checkRawBytes([]byte("a\tb\nc\rd")); err != nil {
		t.Fatalf("tab/LF/CR rejected: %v", err)
	}
}

func TestCompileTracingPolicySchema_CompileError(t *testing.T) {
	bad := `
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
spec:
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        type: 12345
`
	if _, err := compileTracingPolicySchema([]byte(bad)); err == nil {
		t.Fatalf("expected a schema compile error")
	}
}

func TestCompileTracingPolicySchema_RealCRD(t *testing.T) {
	if _, err := compileTracingPolicySchema([]byte(minimalCRD)); err != nil {
		t.Fatalf("compile minimal CRD: %v", err)
	}
	if _, err := compileTracingPolicySchema([]byte("not: valid: yaml: [")); err == nil {
		t.Fatalf("expected parse error")
	}
}

const minimalCRD = `
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: tracingpolicies.cilium.io
spec:
  group: cilium.io
  names:
    kind: TracingPolicy
    plural: tracingpolicies
  scope: Cluster
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        type: object
        properties:
          apiVersion:
            type: string
          kind:
            type: string
          metadata:
            type: object
          spec:
            type: object
            properties:
              kprobes:
                type: array
                items:
                  type: object
                  properties:
                    call:
                      type: string
`
