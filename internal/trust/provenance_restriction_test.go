package trust_test

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

// TestProvenanceVerifier_OnlyCalledFromAgentReverify is the required test
// for docs/reviews/step-04c-review.md R4C-2: (*trust.Root).ProvenanceVerifier
// ignores root metadata expiry entirely, which is correct ONLY for
// re-confirming the provenance of an already-accepted artifact (the LKG
// re-verification in internal/agent/reverify.go). It must never be used on
// an acceptance path (where TargetsVerifier's expiry check is a security
// control, not an inconvenience), so this statically scans every non-test,
// non-vendored .go file in the module for calls to a method named
// "ProvenanceVerifier" and fails if any call site is outside
// internal/agent/reverify.go.
func TestProvenanceVerifier_OnlyCalledFromAgentReverify(t *testing.T) {
	root := moduleRoot(t)
	const allowedCaller = "internal/agent/reverify.go"

	var callers []string
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor", "third_party", "dist", ".git", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ProvenanceVerifier" {
				return true
			}
			callers = append(callers, rel)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(callers) == 0 {
		t.Fatal("no ProvenanceVerifier call sites found at all; this test's AST matching is almost certainly broken, not the repository")
	}
	var bad []string
	for _, c := range callers {
		if c != allowedCaller {
			bad = append(bad, c)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("ProvenanceVerifier called outside %s: %v", allowedCaller, bad)
	}
}

// moduleRoot walks up from the working directory to find the directory
// containing go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from internal/trust")
		}
		dir = parent
	}
}
