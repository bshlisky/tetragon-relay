package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
)

// TestApplyResult_NoPathSendsStatusUnspecified is the R6B-1 / ADR 0037
// proof that no code path sends STATUS_UNSPECIFIED. It has two halves:
//
//  1. TestApplyResult_OnlyWrappedByApplyResultMessage: every non-test Go
//     file in this repository that builds an AgentMessage carrying an
//     ApplyResult does so inside applyResultMessage, and nowhere else.
//  2. This test: applyResultMessage never lets STATUS_UNSPECIFIED (or a
//     number this build does not define) through; every defined status
//     other than STATUS_UNSPECIFIED passes unchanged.
func TestApplyResult_NoPathSendsStatusUnspecified(t *testing.T) {
	for _, st := range []controlv1.ApplyResult_Status{controlv1.ApplyResult_STATUS_UNSPECIFIED, controlv1.ApplyResult_Status(99), controlv1.ApplyResult_Status(-1)} {
		m := applyResultMessage(&controlv1.ApplyResult{Status: st, Detail: "early return"})
		got := m.GetApplyResult()
		if got.GetStatus() != controlv1.ApplyResult_APPLY_FAILED {
			t.Fatalf("status %d sent as %s, want APPLY_FAILED", int32(st), got.GetStatus())
		}
		if !strings.Contains(got.GetDetail(), "not applied") || !strings.Contains(got.GetDetail(), "early return") {
			t.Fatalf("detail = %q", got.GetDetail())
		}
	}
	for n, name := range controlv1.ApplyResult_Status_name {
		st := controlv1.ApplyResult_Status(n)
		if st == controlv1.ApplyResult_STATUS_UNSPECIFIED {
			continue
		}
		if got := applyResultMessage(&controlv1.ApplyResult{Status: st}).GetApplyResult().GetStatus(); got != st {
			t.Fatalf("%s sent as %s", name, got)
		}
	}
	// The zero value of the whole message, the case R6B-1 names.
	if got := applyResultMessage(&controlv1.ApplyResult{}).GetApplyResult().GetStatus(); got == controlv1.ApplyResult_STATUS_UNSPECIFIED {
		t.Fatal("ApplyResult{} sent with STATUS_UNSPECIFIED")
	}
}

// TestApplyResult_OnlyWrappedByApplyResultMessage scans every non-test,
// non-generated Go file under internal/ and cmd/ for a composite literal
// of controlv1.AgentMessage_ApplyResult and requires that the only one
// is inside internal/agent's applyResultMessage.
func TestApplyResult_OnlyWrappedByApplyResultMessage(t *testing.T) {
	root := filepath.Join("..", "..")
	var found []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				ast.Inspect(decl, func(n ast.Node) bool {
					cl, isLit := n.(*ast.CompositeLit)
					if !isLit {
						return true
					}
					sel, isSel := cl.Type.(*ast.SelectorExpr)
					if !isSel || sel.Sel.Name != "AgentMessage_ApplyResult" {
						return true
					}
					where := "<package level>"
					if ok {
						where = fn.Name.Name
					}
					found = append(found, filepath.ToSlash(path)+":"+where)
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	want := filepath.ToSlash(filepath.Join(root, "internal", "agent", "bundle.go")) + ":applyResultMessage"
	if len(found) != 1 || found[0] != want {
		t.Fatalf("AgentMessage_ApplyResult is built at %v; want only %s", found, want)
	}
}
