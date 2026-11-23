package guard

import (
	"encoding/json"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestProtectedLists_BothUsrmergeSpellingsPresent is architect review item
// C1's defensive check: every protectedBinaries/protectedPaths entry that
// has a usrmerge-aliasable prefix must have its alias also present in the
// same list, since paths.go's matching relies entirely on both literal
// spellings being separate list entries (not on converting values at
// match time — see protected.go's doc comment for why that is a
// correctness trap).
func TestProtectedLists_BothUsrmergeSpellingsPresent(t *testing.T) {
	check := func(name string, list []string) {
		set := make(map[string]bool, len(list))
		for _, p := range list {
			set[p] = true
		}
		for _, p := range list {
			alias, ok := usrmergeAlias(p)
			if !ok {
				continue
			}
			if !set[alias] {
				t.Errorf("%s: %q has usrmerge alias %q, which is not also present in the list", name, p, alias)
			}
		}
	}
	check("protectedBinaries", protectedBinaries)
	check("protectedPaths", protectedPaths)
}

// TestCRD_MatchBinariesMaxItemsOne is architect review item C1's required
// check: checkSelectorG1 rejecting a selector with more than one
// matchBinaries entry is only meaningful defense-in-depth if the pinned
// CRD itself still caps matchBinaries (and matchParentBinaries) at exactly
// one entry for every hook type; this test fails loudly if a future
// Tetragon version relaxes that cap without this project noticing.
func TestCRD_MatchBinariesMaxItemsOne(t *testing.T) {
	data, err := os.ReadFile("../../third_party/tetragon/v1.8.0/cilium.io_tracingpolicies.yaml")
	if err != nil {
		t.Fatalf("read vendored CRD: %v", err)
	}
	var root interface{}
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse vendored CRD: %v", err)
	}
	schemaJSON, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic interface{}
	if err := json.Unmarshal(schemaJSON, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	found := 0
	var walk func(node interface{}, path string)
	walk = func(node interface{}, path string) {
		m, ok := node.(map[string]interface{})
		if !ok {
			if arr, ok := node.([]interface{}); ok {
				for i, e := range arr {
					walk(e, path)
					_ = i
				}
			}
			return
		}
		if path == "matchBinaries" || path == "matchParentBinaries" {
			found++
			maxItems, ok := m["maxItems"]
			if !ok {
				t.Errorf("%s schema node has no maxItems constraint", path)
			} else if n, ok := maxItems.(float64); !ok || n != 1 {
				t.Errorf("%s schema node maxItems = %v, want 1", path, maxItems)
			}
		}
		for k, v := range m {
			walk(v, k)
		}
	}
	walk(generic, "")

	// kprobes, fentries, tracepoints, uprobes and lsmhooks each declare
	// their own selectors->matchBinaries/matchParentBinaries schema node,
	// so there should be several occurrences, not just one.
	if found < 2 {
		t.Fatalf("found only %d matchBinaries/matchParentBinaries schema nodes in the vendored CRD; expected several (one per hook type)", found)
	}
}
