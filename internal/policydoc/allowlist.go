package policydoc

import "fmt"

// Step 2 prompt Part B4: apiVersion/kind allowlist, as declared on the
// pinned Tetragon CRD (third_party/tetragon/v1.8.0/cilium.io_tracingpolicies.yaml):
// group "cilium.io", kind "TracingPolicy" is Cluster-scoped (line ~16-18 of
// the CRD); TracingPolicyNamespaced is a separate, Namespaced-scope CRD
// this project does not vendor at all (see that CRD's README) because
// there is no Kubernetes here (architecture doc section 1.2) to have
// namespaces in.
const (
	requiredAPIVersion = "cilium.io/v1alpha1"
	requiredKind       = "TracingPolicy"
)

// kubernetesOnlySelectorFields are TracingPolicySpec fields
// (pkg/k8s/apis/cilium.io/v1alpha1/tracing_policy_types.go:106-134 in the
// pinned source) backed by Kubernetes `metav1.LabelSelector` semantics:
// podSelector and containerSelector match against pod/container labels
// that do not exist on a bare RHEL host; hostSelector and nodeSelector are
// also LabelSelector-typed and, per their own doc comments in that file,
// exist to choose between "host vs pod workloads" and to select Kubernetes
// Node objects by label — neither concept exists outside Kubernetes either.
// On bare RHEL these fields would either match nothing (silently disabling
// a policy the approvers believed was active) or be accepted with
// unclear semantics, which is exactly the false-assurance risk the step 2
// prompt calls out for "podSelector, containerSelector, namespace
// selectors". The CRD has no field literally named "namespace selector";
// this is the project's interpretation of that phrase, recorded here and
// in docs/reports/step-02b.md per the "ambiguity: implement the
// interpretation that rejects more" rule.
var kubernetesOnlySelectorFields = []string{"podSelector", "containerSelector", "hostSelector", "nodeSelector"}

// rejectedHookTypeFields are TracingPolicySpec hook-type fields that exist
// in the pinned CRD but are not in the step 2 prompt's allowed set
// (kprobes, tracepoints, uprobes, lsmhooks).
var rejectedHookTypeFields = []string{"usdts", "fentries"}

// checkAllowlist implements Part B4 against the generic decoded document
// (decoded with json.Decoder.UseNumber so B3's schema validation and this
// check see the same value).
func checkAllowlist(doc map[string]interface{}) error {
	apiVersion, _ := doc["apiVersion"].(string)
	if apiVersion != requiredAPIVersion {
		return fmt.Errorf("%w: got %q, want %q", ErrUnsupportedAPIVersion, apiVersion, requiredAPIVersion)
	}
	kind, _ := doc["kind"].(string)
	if kind != requiredKind {
		return fmt.Errorf("%w: got %q, want %q", ErrUnsupportedKind, kind, requiredKind)
	}

	spec, _ := doc["spec"].(map[string]interface{})
	if spec == nil {
		return nil
	}

	for _, field := range kubernetesOnlySelectorFields {
		if isPresentNonNull(spec[field]) {
			return fmt.Errorf("%w: spec.%s", ErrKubernetesSelector, field)
		}
	}
	for _, field := range rejectedHookTypeFields {
		if isPresentNonNull(spec[field]) {
			return fmt.Errorf("%w: spec.%s", ErrUnsupportedHookType, field)
		}
	}
	// Loader events are a distinct, undocumented-for-this-project hook
	// mechanism outside the four allowed hook types; only an explicit
	// "false" (or absent) value is accepted. Per architecture doc
	// section 7.5's "cap" posture and this step's "reject more" rule.
	if loader, ok := spec["loader"].(bool); ok && loader {
		return fmt.Errorf("%w: spec.loader", ErrUnsupportedHookType)
	}

	return nil
}

// isPresentNonNull reports whether a decoded JSON field was present with a
// non-null value: nil covers both "key absent" (Go zero value for a missing
// map entry) and an explicit JSON `null`.
func isPresentNonNull(v interface{}) bool {
	return v != nil
}
