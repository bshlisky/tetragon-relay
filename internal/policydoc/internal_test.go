package policydoc

// White-box tests exercising defensive branches that cannot be reached
// through Parse once a hardened yaml.Node tree is guaranteed (exact
// precedent: internal/trust/internal_test.go from step 1, which does the
// same for defensive branches `verifyRoleThreshold` can never see through
// any public API once dsse.ParseEnvelope's own checks run first).

import (
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestToCanonicalValue_UnexpectedKind(t *testing.T) {
	n := &yaml.Node{Kind: yaml.AliasNode}
	if _, err := toCanonicalValue(n); err == nil {
		t.Fatalf("expected error for alias node reaching toCanonicalValue directly")
	}
}

func TestScalarToCanonicalValue_BinaryAndUnsupportedTag(t *testing.T) {
	bin := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!binary", Value: "aGVsbG8="}
	v, err := scalarToCanonicalValue(bin)
	if err != nil {
		t.Fatalf("valid base64: %v", err)
	}
	if v.(cvString) != "aGVsbG8=" {
		t.Fatalf("value = %v", v)
	}

	badBin := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!binary", Value: "not base64!"}
	if _, err := scalarToCanonicalValue(badBin); err == nil {
		t.Fatalf("expected error for invalid base64")
	}

	unsupported := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!timestamp", Value: "2020-01-01"}
	if _, err := scalarToCanonicalValue(unsupported); err == nil {
		t.Fatalf("expected error for unsupported tag")
	}
}

func TestWalk_UnexpectedKindAndUnbalancedMapping(t *testing.T) {
	h := &hardenedYAML{}
	if err := h.walk(&yaml.Node{Kind: 99}, 1); err == nil {
		t.Fatalf("expected error for unknown node kind")
	}

	h2 := &hardenedYAML{}
	odd := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "onlykey"},
		},
	}
	if err := h2.walkMapping(odd, 1); err == nil {
		t.Fatalf("expected error for unbalanced mapping")
	}
}

func TestParseHardenedYAML_TopLevelNotMapping(t *testing.T) {
	if _, err := parseHardenedYAML([]byte("- a\n- b\n")); err == nil {
		t.Fatalf("expected error for a top-level sequence")
	}
}

func TestWalkMapping_AliasAsKey(t *testing.T) {
	// An anchor must be rejected outright (B1), which means a real YAML
	// document can never reach the alias-as-key branch below through a
	// live anchor/alias pair (the anchor itself is always rejected
	// first, in document order). Exercised directly, as a defensive
	// branch, the same way the synthetic-node tests above do.
	h := &hardenedYAML{}
	n := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.AliasNode},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "y"},
		},
	}
	if err := h.walkMapping(n, 1); !errors.Is(err, ErrYAMLAlias) {
		t.Fatalf("error = %v, want ErrYAMLAlias", err)
	}
}

func TestParseHardenedYAML_TooManyNodes(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("a:\n")
	for i := 0; i < 25000; i++ {
		sb.WriteString("- x\n")
	}
	if _, err := parseHardenedYAML([]byte(sb.String())); !errors.Is(err, ErrYAMLTooManyNodes) {
		t.Fatalf("error = %v, want ErrYAMLTooManyNodes", err)
	}
}

func TestTypedModelActionWalk_MatchReturnActions(t *testing.T) {
	d := &rawDoc{
		Spec: rawSpec{
			KProbes: []rawKProbeSpec{{
				Selectors: []rawSelector{{
					MatchReturnActions: []rawActionSelector{{Action: "TrackSock"}},
				}},
			}},
		},
	}
	got := d.typedModelActionWalk()
	if len(got) != 1 || got[0] != "TrackSock" {
		t.Fatalf("got %v", got)
	}
}

func TestParse_B6_IntegerOverflowRejectedByTypedModel(t *testing.T) {
	// A JSON-schema-valid integer ("type: integer" has no range bound in
	// the vendored CRD for KProbeArg.index) that overflows the typed
	// model's uint32 Index field must be rejected, not silently
	// truncated or wrapped: this is exactly the gap B6's exact Go typing
	// (on top of B3's schema check) exists to close.
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "x"
    args:
    - index: 99999999999
      type: "int"
`
	_, err := Parse("sample", y)
	if !errors.Is(err, ErrModelDecode) {
		t.Fatalf("error = %v, want ErrModelDecode", err)
	}
}

func TestRenderNumber_FloatLiteralNeedingReresolve(t *testing.T) {
	// "1_000.5" is not valid JSON number syntax (underscore digit
	// separator) but yaml.v3 resolves it to a float64 after stripping
	// underscores; renderNumber must re-render it exactly.
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!float", Value: "1_000.5"}
	got, err := renderNumber(n)
	if err != nil {
		t.Fatalf("renderNumber: %v", err)
	}
	if got != "1000.5" {
		t.Fatalf("got %q, want 1000.5", got)
	}
}

func TestRenderNumber_UnexpectedType(t *testing.T) {
	// renderNumber is only ever called by scalarToCanonicalValue for a
	// node tagged !!int or !!float; calling it directly with a node
	// whose literal is not valid JSON number syntax but resolves (via
	// the node's own tag) to a non-numeric Go type exercises the
	// "unexpected Go type" default branch defensively.
	notNumeric := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!timestamp", Value: "2020-01-01T00:00:00Z"}
	if _, err := renderNumber(notNumeric); err == nil {
		t.Fatalf("expected an unexpected-type error")
	}
}

func TestWalkMapping_KeySideRejections(t *testing.T) {
	longKey := strings.Repeat("a", 5000)
	cases := []struct {
		name string
		n    *yaml.Node
		want error
	}{
		{"key_anchor", mappingWithKey(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "x", Anchor: "n"}), ErrYAMLAnchor},
		{"key_explicit_tag", mappingWithKey(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "x", Style: yaml.TaggedStyle}), ErrYAMLExplicitTag},
		{"key_too_long", mappingWithKey(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: longKey}), ErrYAMLScalarTooLarge},
		{"key_ambiguous", mappingWithKey(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "yes"}), ErrYAMLAmbiguousScalar},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &hardenedYAML{}
			if err := h.walkMapping(tc.n, 1); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func mappingWithKey(key *yaml.Node) *yaml.Node {
	return &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			key,
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "v"},
		},
	}
}

func TestParseHardenedYAML_SyntaxError(t *testing.T) {
	if _, err := parseHardenedYAML([]byte("a: [1,2\n")); !errors.Is(err, ErrYAMLParse) {
		t.Fatalf("error = %v, want ErrYAMLParse", err)
	}
}

func TestDecodeGeneric_InvalidJSON(t *testing.T) {
	if _, err := decodeGeneric([]byte("{not valid")); err == nil {
		t.Fatalf("expected an error")
	}
}

func TestCheckAllowlist_NilSpec(t *testing.T) {
	doc := map[string]interface{}{
		"apiVersion": requiredAPIVersion,
		"kind":       requiredKind,
	}
	if err := checkAllowlist(doc); err != nil {
		t.Fatalf("unexpected error for a document with no spec: %v", err)
	}
}

func TestBuildHooks_UnknownMacroPropagatesForEveryHookKind(t *testing.T) {
	cases := []struct {
		name string
		doc  *rawDoc
	}{
		{"tracepoint", &rawDoc{Spec: rawSpec{Tracepoints: []rawTracepointSpec{{Selectors: []rawSelector{{Macros: []string{"missing"}}}}}}}},
		{"uprobe", &rawDoc{Spec: rawSpec{UProbes: []rawUProbeSpec{{Selectors: []rawSelector{{Macros: []string{"missing"}}}}}}}},
		{"lsmhook", &rawDoc{Spec: rawSpec{LsmHooks: []rawLsmHookSpec{{Selectors: []rawSelector{{Macros: []string{"missing"}}}}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildHooks(tc.doc); !errors.Is(err, ErrUnknownMacro) {
				t.Fatalf("error = %v, want ErrUnknownMacro", err)
			}
		})
	}
}

func TestCheckActionCompleteness_SameLengthDifferentContent(t *testing.T) {
	generic := map[string]interface{}{
		"matchActions": []interface{}{
			map[string]interface{}{"action": "Post"},
			map[string]interface{}{"action": "Post"},
		},
	}
	typed := &rawDoc{
		Spec: rawSpec{
			KProbes: []rawKProbeSpec{{
				Selectors: []rawSelector{{
					MatchActions: []rawActionSelector{{Action: "Post"}, {Action: "Sigkill"}},
				}},
			}},
		},
	}
	if err := checkActionCompleteness(generic, typed); !errors.Is(err, ErrUnmodeledAction) {
		t.Fatalf("error = %v, want ErrUnmodeledAction", err)
	}
}

func TestParse_LargeUint64AndFractionalFloatLiterals(t *testing.T) {
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "x"
    selectors:
    - matchActions:
      - action: "Override"
        argNewAddr: 18_446_744_073_709_551_615
`
	d, err := Parse("sample", y)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(string(d.CanonicalJSON()), `"argNewAddr":18446744073709551615`) {
		t.Fatalf("uint64 literal not re-rendered: %s", d.CanonicalJSON())
	}
}
