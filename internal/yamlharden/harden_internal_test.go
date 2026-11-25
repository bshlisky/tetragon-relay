package yamlharden

// White-box tests exercising defensive branches that cannot be reached
// through Parse once a hardened yaml.Node tree is guaranteed. Moved
// verbatim (apart from the package clause and parseHardenedYAML -> Parse)
// from internal/policydoc/internal_test.go and unit_test.go by
// docs/prompts/step-06a.md Part B2, when this package was extracted from
// internal/policydoc: these tests exercise the walker, which now lives
// here. internal/policydoc keeps its own black-box Parse tests
// unchanged.

import (
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

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

func TestParse_TopLevelNotMapping(t *testing.T) {
	if _, err := Parse([]byte("- a\n- b\n")); err == nil {
		t.Fatalf("expected error for a top-level sequence")
	}
}

func TestWalkMapping_AliasAsKey(t *testing.T) {
	// An anchor must be rejected outright, which means a real YAML
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

func TestParse_TooManyNodes(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("a:\n")
	for i := 0; i < 25000; i++ {
		sb.WriteString("- x\n")
	}
	if _, err := Parse([]byte(sb.String())); !errors.Is(err, ErrYAMLTooManyNodes) {
		t.Fatalf("error = %v, want ErrYAMLTooManyNodes", err)
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

func TestParse_SyntaxError(t *testing.T) {
	if _, err := Parse([]byte("a: [1,2\n")); !errors.Is(err, ErrYAMLParse) {
		t.Fatalf("error = %v, want ErrYAMLParse", err)
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
