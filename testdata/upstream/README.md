# Upstream TracingPolicy corpus (Tetragon v1.8.0)

Every example `TracingPolicy` document under
`examples/tracingpolicy/` in `cilium/tetragon` at tag `v1.8.0`
(commit `a5a667837d4b1ecd9018797994bb4e39b98702e1`), flattened into this
directory (path separators replaced with `__`) so each file is addressable
by a single name in Go test tables.

`MANIFEST.tsv` records, for each file: `<flat name>\t<original repo-relative
path>\t<sha256 of the original file content>`. The flattened copies here are
byte-identical to the originals; re-run the commands in
`third_party/tetragon/v1.8.0/README.md`'s "Re-vendoring procedure" against
`examples/tracingpolicy/` (same tag) to regenerate and diff this directory
if upstream content is ever suspected to have changed.

`internal/policydoc`'s and `internal/guard`'s tests run every file in this
corpus through `Parse` and `Check`; `docs/reports/step-02b.md` section 11
has the per-file result table and rationale (most are rejected for using
Kubernetes-only selectors or hook types this project's architecture
explicitly excludes — see architecture doc section 1.2).

Licensed Apache-2.0 by the Tetragon authors (SPDX headers in the originals);
reproduced here only as test fixtures.
