package tetra

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// allowedRPCs is step 3 prompt Part B1's fixed, typed allowlist. Nothing
// else may ever be called on the stub field.
var allowedRPCs = map[string]bool{
	"AddTracingPolicy":     true,
	"DeleteTracingPolicy":  true,
	"ListTracingPolicies":  true,
	"EnableTracingPolicy":  true,
	"DisableTracingPolicy": true,
	"GetHealth":            true,
	"GetVersion":           true,
	"GetEvents":            true,
}

// TestAllowlist_NoOtherRPCsReferenced statically scans every non-test .go
// file in this package for "<ident>.stub.<Method>(...)" call expressions
// and fails if Method is not in allowedRPCs. This is Part B1's required
// test: it fails the build if this package is ever extended to call
// ConfigureTracingPolicy, ListSensors, GetInfo, or any other
// FineGuidanceSensors RPC.
func TestAllowlist_NoOtherRPCsReferenced(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	called := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// Match "<something>.stub.<Method>(...)": sel.X must itself
			// be a selector whose Sel is "stub".
			inner, ok := sel.X.(*ast.SelectorExpr)
			if !ok || inner.Sel.Name != "stub" {
				return true
			}
			called[sel.Sel.Name] = true
			return true
		})
	}
	if len(called) == 0 {
		t.Fatal("no RPC calls found at all; this test's AST matching is almost certainly broken, not the package")
	}
	var bad []string
	for m := range called {
		if !allowedRPCs[m] {
			bad = append(bad, m)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("internal/tetra calls RPC(s) outside the step 3 prompt Part B1 allowlist: %v", bad)
	}
}
