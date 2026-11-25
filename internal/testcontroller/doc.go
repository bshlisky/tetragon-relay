// Package testcontroller implements docs/prompts/step-05b.md Part E2: a
// minimal reference implementation of the controller's stream gateway,
// used only in this repository's own tests (internal/controlclient's
// integration test) and by cmd/testcontroller (build tag "testserver").
// It implements only what E2 asks for: the TLS profile, the client
// certificate checks architecture doc 6.3 steps 1-2 describe, and the
// Hello/HelloAck exchange. It is explicitly NOT a production controller:
// no bundle distribution, no heartbeat tracking beyond acknowledging
// Hello, no persistence.
//
// This package carries no build tag itself (unlike cmd/testcontroller,
// which does): nothing in a production build ever imports it, the same
// way internal/testvectors carries no tag despite existing only to
// support cmd/bundlesign-test (tag "testtools") and this project's own
// test suites.
package testcontroller
