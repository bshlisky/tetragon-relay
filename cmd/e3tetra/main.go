//go:build e3

// Command e3tetra is a small CLI wrapper around internal/tetra, used by
// the E3 CI job's shell steps to set up and check the "pre-applied LKG"
// baseline S1/S2/S4/S5 all assert stays unchanged, without needing a Go
// test binary for it. Like cmd/e3controller, it shares no build tag with
// relayd itself (C4) and is never part of production.
//
// It deliberately talks to Tetragon directly (internal/tetra.Client),
// bypassing relay's own apply/store pipeline entirely: the scenarios
// this tool supports only need something loaded in Tetragon before
// relayd starts and need to prove relayd never touches it, regardless
// of how it got there -- they are not testing internal/apply/store
// themselves (those have their own, separate integration coverage,
// internal/apply/integration_test.go).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "e3tetra: FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("e3tetra", flag.ContinueOnError)
	socket := fs.String("socket", "/var/run/tetragon/tetragon.sock", "Tetragon gRPC unix socket")
	tetragonBinary := fs.String("tetragon-binary", "", "path to the Tetragon daemon binary (for internal/tetra's own socket-peer verification)")
	relayGroup := fs.String("relay-group", "tetragon-relay", "POSIX group the socket must be owned by")
	mode := fs.String("mode", "", "preload | list | check | delete")
	domain := fs.String("domain", "", "delete mode: the policy's domain (relayd loads its policies in domain \"relay-managed\")")
	policyName := fs.String("policy-name", "e3-baseline", "preload mode: the TracingPolicy's metadata.name")
	expectNames := fs.String("expect-names", "", "check mode: comma-separated list of policy names that must be exactly what is loaded (order-independent)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tetragonBinary == "" {
		return fmt.Errorf("--tetragon-binary is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := tetra.Dial(ctx, tetra.Config{
		SocketPath: *socket, TetragonBinaryPath: *tetragonBinary, RelayGroupName: *relayGroup,
		// GitHub-hosted runners have SELinux disabled, same as
		// internal/apply/integration_test.go's own dialIntegration.
		AllowSELinuxDisabled: true,
	})
	if err != nil {
		return fmt.Errorf("dial Tetragon: %w", err)
	}
	defer func() { _ = client.Close() }()

	switch *mode {
	case "preload":
		return preload(ctx, client, *policyName)
	case "list":
		return list(ctx, client)
	case "check":
		return check(ctx, client, *expectNames)
	case "delete":
		// Step 6b S11: an out-of-band delete through Tetragon's own
		// socket, the same DeleteTracingPolicy RPC `tetra tracingpolicy
		// delete` issues, of a policy relayd manages.
		if err := client.DeleteTracingPolicy(ctx, *policyName, *domain); err != nil {
			return fmt.Errorf("DeleteTracingPolicy(%q, domain %q): %w", *policyName, *domain, err)
		}
		fmt.Printf("e3tetra: deleted policy %q (domain %q) out of band\n", *policyName, *domain)
		return nil
	default:
		return fmt.Errorf("--mode must be preload, list, check or delete, got %q", *mode)
	}
}

func preload(ctx context.Context, client *tetra.Client, name string) error {
	if err := client.AddTracingPolicy(ctx, canaryPolicyYAML(name), ""); err != nil {
		return fmt.Errorf("AddTracingPolicy: %w", err)
	}
	fmt.Printf("e3tetra: loaded baseline policy %q\n", name)
	return nil
}

func list(ctx context.Context, client *tetra.Client) error {
	statuses, err := client.ListTracingPolicies(ctx, "")
	if err != nil {
		return fmt.Errorf("ListTracingPolicies: %w", err)
	}
	names := policyNames(statuses)
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func check(ctx context.Context, client *tetra.Client, expect string) error {
	if expect == "" {
		return fmt.Errorf("--expect-names is required for check mode")
	}
	statuses, err := client.ListTracingPolicies(ctx, "")
	if err != nil {
		return fmt.Errorf("ListTracingPolicies: %w", err)
	}
	got := policyNames(statuses)
	want := strings.Split(expect, ",")
	sort.Strings(want)
	if !equalStrings(got, want) {
		return fmt.Errorf("loaded policies = %v, want exactly %v (relayd must never change what Tetragon has loaded in this step)", got, want)
	}
	fmt.Printf("e3tetra: loaded policies unchanged: %v\n", got)
	return nil
}

func policyNames(statuses []tetra.TracingPolicyStatus) []string {
	names := make([]string, 0, len(statuses))
	for _, s := range statuses {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// canaryPolicyYAML is deliberately inert (it only ever matches a binary
// path, "/tmp/e3-baseline-placeholder", that is never exec'd during this
// job): S1/S2/S4/S5 only need something loaded, never actually
// triggered, to prove relayd leaves Tetragon's loaded set alone.
func canaryPolicyYAML(name string) string {
	return fmt.Sprintf(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: %q
spec:
  kprobes:
  - call: "security_bprm_check"
    syscall: false
    selectors:
      - matchBinaries:
        - operator: "In"
          values:
          - "/tmp/e3-baseline-placeholder"
        matchActions:
        - action: "Post"
`, name)
}
