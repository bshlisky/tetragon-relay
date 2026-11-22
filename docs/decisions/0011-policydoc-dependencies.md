# ADR 0011: Dependencies added for policy ingestion (step 2, Part B)

## Status

Accepted.

## Context

Step 2 Part B (`internal/policydoc`) must parse arbitrary, untrusted policy
YAML defensively (B1: reject anchors/aliases/merge keys/explicit tags,
duplicate keys, YAML 1.1 implicit-typing ambiguity, depth/size limits) and
validate the result against Tetragon's `TracingPolicy` CRD OpenAPI schema
(B3), treating it as closed. ADR 0001 (step 1) deliberately hand-wrote DSSE,
TUF and strict-JSON logic to avoid a supply-chain dependency for the
*signature and schema* layer; the same reasoning does not extend to a full
YAML 1.1/1.2-aware parser or a JSON Schema (draft 2020-12 /
`x-kubernetes-*`-adjacent, OpenAPI v3 subset) validator — both are large,
easy-to-get-subtly-wrong parsers whose correctness is better delegated to
widely used, reviewed libraries than reimplemented under this project's time
budget. The prompt for this step explicitly permits this with a justifying
ADR.

## Decision

Two dependencies are added:

| Module | Version | Why |
| --- | --- | --- |
| `gopkg.in/yaml.v3` | v3.0.1 | Its `yaml.Node` API exposes the tag, anchor, alias and merge-key information B1 needs to reject *before* any value conversion happens — a map-based decode (`yaml.Unmarshal` into `map[string]interface{}`) would silently resolve aliases and merge keys and lose the YAML 1.1 vs quoted-scalar distinction B1 requires. v3.0.1 (2022-04) is the latest v3 tag; no v4 of this module exists as of this writing. It is the de facto standard Go YAML library (used by Kubernetes, Helm, and most of the Go ecosystem) and is already an indirect dependency of nothing else in this repo's module graph, so it adds no transitive surface. |
| `github.com/santhosh-tekuri/jsonschema/v5` | v5.3.1 | Validates the canonicalized policy JSON against the vendored, closed `TracingPolicy` CRD OpenAPI schema (B3). Chosen over hand-writing a schema validator because the CRD schema is ~9,700 lines of OpenAPI v3 with enums, patterns, `oneOf`-shaped `x-kubernetes-validations` (CEL, not evaluated here) and nested `additionalProperties`; a hand-rolled subset validator would either be incomplete (silently accepting fields it doesn't know to check) or would duplicate most of a JSON Schema implementation anyway. v5 (not the newer v6, which changed its API surface and the resource-loading model) was picked for its simpler, stable `Compiler`/`Schema` API and because OpenAPI v3's schema dialect maps directly onto JSON Schema draft 2019-09/2020-12 keywords (`properties`, `additionalProperties`, `required`, `enum`, `type`, `items`, `minLength`, `pattern`, …) that both v5 and v6 support identically for this project's purposes. v5.3.1 (2023-07) is its final/latest v5 release. |

Both are leaf dependencies for this project (neither pulls in network,
filesystem-watching, or code-generation machinery); `go mod vendor` output
is committed as with every other dependency (architecture doc section 8.12).

## Consequences

- `internal/policydoc` performs structural YAML hardening (B1) with
  `yaml.Node`, not `yaml.Unmarshal`, specifically so that anchors, aliases,
  merge keys and explicit tags are visible as distinct node kinds/tags
  *before* any value is produced, rather than being silently resolved.
- CRD schema validation is real (draft-level JSON Schema semantics), not a
  hand-rolled approximation; `internal/policydoc/schema.go` additionally
  rewrites the vendored schema to inject `additionalProperties: false`
  wherever the upstream schema declares `properties` without an explicit
  `additionalProperties`, closing it per the step 2 prompt's requirement
  (see docs/reports/step-02b.md section 12 for the full list of such
  places).
- `govulncheck` and the SBOM now also cover these two dependencies'
  transitive graphs (both have none beyond the Go standard library, checked
  via `go mod graph` at the time of this ADR).
