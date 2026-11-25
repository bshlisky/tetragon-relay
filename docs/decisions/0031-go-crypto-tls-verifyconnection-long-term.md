# ADR 0031: Go's crypto/tls with VerifyConnection is the long-term control-channel TLS implementation

## Status

Accepted.

## Context

`docs/reviews/step-05b-review.md`'s open question 2 asked whether
`internal/controlclient`'s approach -- Go's standard-library `crypto/tls`,
`InsecureSkipVerify` plus a `VerifyConnection` callback that performs the
entire server-authentication check itself (chain verification against the
controller CA bundle, `ExtKeyUsageServerAuth`, an exact URI SAN match against
the configured controller SPIFFE ID, TLS 1.3 version pinning and an allowed
cipher suite, as of ADR R5B-1 using an injected clock) -- is acceptable as a
long-term design, or whether a dedicated SPIFFE/mTLS library (e.g.
`github.com/spiffe/go-spiffe`) or a different TLS stack should replace it
before production.

The review's own verdict (step-05b-review.md, "Answers to the open
questions", item 2) is: "Acceptable long-term; stay on the standard library.
TLS 1.3 suites are all AEAD. In FIPS 140-3 mode Go limits TLS 1.3 to the
AES-GCM suites, so the post-handshake check is defense in depth there. Record
this in an ADR (Accepted) and close the question." This ADR records that
decision and the reasoning behind it.

## Decision

`internal/controlclient` continues to use Go's standard-library `crypto/tls`
with `InsecureSkipVerify: true` and a `VerifyConnection` callback doing full
manual verification (`tlsconfig.go`), rather than adopting a third-party
SPIFFE/mTLS library or a different TLS implementation, for the life of this
project.

Reasoning:

1. **The pattern this project uses is the same one `go-spiffe`'s own
   `tlsconfig` package uses internally** for the identical reason
   (`docs/reports/step-05b.md` section 6 and `tlsconfig.go`'s own doc
   comment): Go's `crypto/tls` and grpc-go's `credentials.NewTLS` both
   auto-populate `Config.ServerName` from the dial target when left empty,
   which would otherwise silently re-enable hostname verification this
   project's DNS/IP-SAN-less certificates (architecture doc 5.1) can never
   pass. Adopting `go-spiffe` would replace this project's own
   `VerifyConnection` with that library's near-identical one, without adding
   new assurance, while adding a new third-party dependency this project's
   working agreement requires an ADR to justify in the first place (no such
   justification exists: the hand-rolled version is ~50 lines, fully
   covered by unit tests, and requires no new supply-chain trust).
2. **TLS 1.3's cipher suites are all AEAD (AES-GCM or ChaCha20-Poly1305);
   there is no legacy CBC/RC4/3DES suite TLS 1.3 could ever negotiate**, so
   the risk a pre-TLS-1.3 cipher-suite restriction mechanism exists to guard
   against (a weak or broken suite being silently accepted) does not apply
   to this protocol version at all. The only suite this project additionally
   excludes, `TLS_CHACHA20_POLY1305_SHA256`, is excluded for
   crypto-policy/FIPS-alignment reasons (architecture doc 6.1, matching RHEL
   `FIPS` crypto-policy), not because it is insecure.
3. **In FIPS 140-3 mode, Go's own TLS 1.3 stack already restricts itself to
   the AES-GCM suites** (the Go FIPS 140-3 Cryptographic Module, ADR 0021,
   rejects `TLS_CHACHA20_POLY1305_SHA256` negotiation outright when the
   module is active). `VerifyConnection`'s post-handshake cipher-suite check
   (ADR'd as a documented deviation in `docs/reports/step-05b.md` section 6,
   since Go's TLS 1.3 stack cannot restrict suite OFFERING pre-handshake) is
   therefore defense in depth on a FIPS-mode build, not the only layer: a
   FIPS-mode agent could never negotiate the forbidden suite in the first
   place, and `VerifyConnection` exists to catch the case where it is not
   running in FIPS mode, or a non-conforming server implementation
   negotiates it anyway.
4. **No alternative considered changes who is authoritative for anything.**
   `docs/server-contract.md` section 2 already tells the backend team the
   agent cannot enforce which suite the gateway's own stack OFFERS; a
   different client-side TLS library would not change that fact, since the
   limitation is in what the TLS 1.3 RFC exposes to a client at all, not in
   any one implementation's API surface.
5. **Switching TLS stacks now would be a substantial, security-sensitive
   rewrite of `internal/controlclient` for a problem this design does not
   have.** This project's "no third-party dependency without an ADR
   justifying it" rule (docs/prompts/step-04b.md's working agreement) cuts
   the other way here: adding `go-spiffe` (or any alternative) is the change
   that would need justifying, and the review found none strong enough
   reviewing the current approach against this project's actual TLS 1.3 /
   FIPS-crypto-policy requirements.

## Consequences

- No code change: this ADR records and closes an already-implemented
  design (`internal/controlclient/tlsconfig.go`), consistent with
  step-05b-review.md's own instruction to "record this in an ADR (Accepted)
  and close the question."
- `docs/prompts/step-06a.md` A2 is satisfied by this ADR's existence; no
  further open question remains on this topic.
- Future TLS-stack changes (e.g. adopting a hybrid ML-KEM group once the
  RHEL crypto stack supports it in FIPS mode, architecture doc 6.1) extend
  `internal/controlclient.Config.Groups` (already a config list, ADR 0022)
  rather than requiring a new TLS implementation; this ADR does not need
  revisiting for that change.
</content>
