# testcontroller

**This is not a production controller.** It is a minimal reference implementation of the
controller's stream gateway handshake only (docs/prompts/step-05b.md Part E2): TLS 1.3,
mutual authentication, the client-certificate checks architecture doc section 6.3 steps 1-2
describe (chain validity via TLS itself, host SPIFFE ID parsing, a denylist, inventory
membership), and the Hello/HelloAck exchange.

It never forwards policy bundles, tracks heartbeats beyond the first Hello, or persists
anything. The full control message loop, trust updates, and bundle distribution are
implemented by the customer's existing backend (see `docs/server-contract.md`), not by this
tool.

Used by:

- `internal/controlclient`'s integration test (build tags `testca,testserver`), as the
  reference server it dials against.
- The backend team, as a runnable reference for the handshake half of the protocol while
  implementing `docs/server-contract.md`.

## Build

```sh
go build -tags testserver -o testcontroller ./cmd/testcontroller
```

Never built as part of a default `go build ./...` (the `testserver` tag gates it out,
matching `cmd/bundlesign-test`'s `testtools` tag precedent).

## Run

```sh
./testcontroller \
  --listen 127.0.0.1:8443 \
  --trust-domain mgmt.example.internal \
  --server-cert server.pem --server-key server.key \
  --client-ca agent-ca.pem
```
