# ADR 0012: Threat T-27 (YAML parser differential) and its mitigation

## Status

Accepted. Proposes a new threat-model row; for architect review alongside
the rest of step 2.

## Context

Architecture doc section 13's threat table (T-01 through T-26) does not
cover a class of bug this step's design has to defend against directly:
the agent's own policy parser (`internal/policydoc`, built on
`gopkg.in/yaml.v3`, ADR 0011) could resolve a YAML document's scalars
differently from whatever YAML/JSON ingestion path Tetragon itself uses
when it later loads the same policy. If the two disagree about even one
value's type or content, the agent could verify, approve and sign off on a
policy that is semantically different from the one actually enforced in
the kernel — silently defeating every other control in this architecture
(INV-1's guarantee that "no TracingPolicy is loaded... unless [it] carries
a valid signature" is worthless if the signed bytes and the loaded
semantics diverge).

Concretely, within just the YAML 1.1 vs 1.2 core schema difference: a
parser that treats `yes`/`no`/`on`/`off` as booleans (YAML 1.1, used by
e.g. PyYAML's default loader and `gopkg.in/yaml.v2`) versus one that treats
them as the literal strings (YAML 1.2 core schema, `gopkg.in/yaml.v3`'s
default behavior — see `internal/policydoc/yamlharden.go`'s
`yaml11AmbiguousExact` doc comment) would produce two different JSON values
from the same bytes. Leading-zero numeric literals (`0755`), sexagesimal
notation (`1:30`), and `.inf`/`.nan` spellings have similar cross-parser
ambiguity.

## Decision

Add to architecture doc section 13's threat table:

| ID | Threat | STRIDE | Adversary | Asset | Attack path | Controls (EP) | L | I | Residual |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-27 | Agent's YAML parser and Tetragon's own policy-loading parser disagree about a scalar's type/value, so the agent verifies a different policy than Tetragon enforces | T | ADV5 (malicious author exploiting the ambiguity), or an honest author's unquoted value being misread | AS6 | Unquoted YAML 1.1-ambiguous scalar (`yes`, `0755`, `1:30`, `.inf`, ...) that a YAML 1.1 reader and `yaml.v3` resolve differently | `internal/policydoc` B1 rejects every such unquoted scalar outright (`ErrYAMLAmbiguousScalar`); B5 sends Tetragon the agent's own canonical JSON bytes, never the original YAML text, so even if Tetragon's loader also accepts JSON input, it is parsing exactly what the agent already resolved, not re-resolving the original YAML independently | L | H | Low |

Two independent, layered mitigations, both already implemented in this
step (not proposed future work):

1. **Reject the ambiguity at the source (B1).** Rather than trying to
   match Tetragon's exact parser behavior (which may itself change across
   versions, or differ between the Kubernetes CRD path and whatever a
   bare-RHEL CLI loader uses — this project found no pinned-source
   confirmation of which YAML library Tetragon's own non-Kubernetes policy
   loading path uses, and per "never guess a fact," does not assume one),
   `internal/policydoc` rejects any unquoted scalar whose resolution could
   plausibly differ between a YAML 1.1 and a YAML 1.2 (or `yaml.v3`-core)
   reading. An author who means the string `"yes"` must quote it; there is
   then no parser left to disagree with.
2. **Never re-parse YAML downstream (B5).** `policydoc.Doc.CanonicalJSON()`
   is deterministic JSON — sorted keys, no insignificant whitespace,
   numbers preserved exactly as the (already-resolved, already-rejected if
   ambiguous) YAML scalar specified. Step 3 (policy apply) must send this
   canonical form to Tetragon, not the original YAML text, so that the
   bytes this project's guardrails analyzed are the same bytes Tetragon's
   own decoder consumes, eliminating the re-parse step where a second
   disagreement could otherwise be introduced.

## Consequences

- A legitimate policy author who writes an unquoted `yes`/`on`/`0755`/etc.
  value gets a clear, typed rejection (`ErrYAMLAmbiguousScalar`) at
  authoring time, not a silent misinterpretation discovered later. This is
  a usability cost, accepted deliberately per "ambiguity: implement the
  interpretation that rejects more."
- This mitigation only covers the ambiguity introduced by one specific,
  well-understood parser disagreement (YAML 1.1 vs 1.2 core-schema implicit
  typing). It does not prove no other divergence between `yaml.v3` and
  Tetragon's own ingestion exists; see docs/reports/step-02b.md's open
  questions for the follow-up this ADR recommends (confirming which YAML
  library Tetragon's non-Kubernetes CLI loader uses, and whether it
  consumes canonical JSON directly or re-parses YAML on the host).
- Step 3 (policy apply, out of scope here) MUST use
  `policydoc.Doc.CanonicalJSON()` as the bytes sent to Tetragon's
  `AddTracingPolicy`, per mitigation 2 above; this ADR records that
  requirement for that step's implementer.
