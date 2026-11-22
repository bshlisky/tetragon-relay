# Vendored Tetragon CRD (v1.8.0)

This directory vendors the `TracingPolicy` CustomResourceDefinition from the
pinned upstream Tetragon release so that `internal/policydoc` can validate
policy YAML against the exact schema the pinned Tetragon version enforces
(architecture doc section 7.2 step 1, step 2 prompt Part B3).

## Source

- Repository: `https://github.com/cilium/tetragon`
- Tag: `v1.8.0` (an annotated tag object `03ddc90df27e36c200e2d60c39f22f7a274559c3`)
- Commit the tag points to: `a5a667837d4b1ecd9018797994bb4e39b98702e1`
  ("Prepare for v1.8.0 release", 2026-10-30)
- File: `pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpolicies.yaml`
- Retrieved via: `git clone --depth 1 --branch v1.8.0 https://github.com/cilium/tetragon.git`

Deliberately NOT vendored: `cilium.io_tracingpoliciesnamespaced.yaml`. Per
architecture doc section 1.2 ("Out of scope: Kubernetes deployments of
Tetragon") and the step 2 prompt ("apiVersion == cilium.io/v1alpha1, kind ==
TracingPolicy (NOT TracingPolicyNamespaced; there is no Kubernetes here)"),
`TracingPolicyNamespaced` bundles are rejected by `policydoc.Parse` (B4)
before schema validation would ever need that CRD's schema.

## File hash

```
$ sha256sum cilium.io_tracingpolicies.yaml
d99daa68c99faeab6a32ea843ab9a381ea2f63666b26e265bf048ac0ab617869
```

`make verify-crd` re-checks this hash in CI so that a future accidental or
malicious edit to the vendored file is caught before it silently changes
what `internal/policydoc` accepts.

## Re-vendoring procedure

```
git clone --depth 1 --branch <new-tag> https://github.com/cilium/tetragon.git /tmp/tetragon-src
cp /tmp/tetragon-src/pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpolicies.yaml \
   third_party/tetragon/<new-version>/cilium.io_tracingpolicies.yaml
sha256sum third_party/tetragon/<new-version>/cilium.io_tracingpolicies.yaml
```

Update this README, `internal/policydoc`'s embedded path, and
`Makefile`'s `verify-crd` target hash together, in the same commit.
