package policydoc

import (
	"os"
	"testing"
)

func TestSmoke_SimpleValidPolicy(t *testing.T) {
	y := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sample"
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    args:
    - index: 0
      type: "linux_binprm"
    selectors:
      - matchBinaries:
        - operator: "In"
          values:
          - "/usr/bin/sample-exec"
        matchActions:
        - action: "Post"
`
	doc, err := Parse("sample", y)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Name() != "sample" {
		t.Fatalf("Name() = %q", doc.Name())
	}
	if len(doc.Hooks()) != 1 {
		t.Fatalf("Hooks() = %d, want 1", len(doc.Hooks()))
	}
	h := doc.Hooks()[0]
	if h.Kind != HookKindKProbe || h.Identifier != "security_bprm_check" {
		t.Fatalf("hook = %+v", h)
	}
	if len(h.Selectors) != 1 || len(h.Selectors[0].MatchActions) != 1 || h.Selectors[0].MatchActions[0].Action != "Post" {
		t.Fatalf("selector = %+v", h.Selectors)
	}
	t.Logf("canonical JSON: %s", doc.CanonicalJSON())
}

func TestSmoke_UpstreamLsmBprmCheck(t *testing.T) {
	data, err := os.ReadFile("../../testdata/upstream/lsm_bprm_check.yaml")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	doc, err := Parse("lsm", string(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.Hooks()) != 1 || doc.Hooks()[0].Kind != HookKindLsmHook {
		t.Fatalf("hooks = %+v", doc.Hooks())
	}
}
