// Package agent implements step-04b.md Part D's relay-agent startup
// sequence: a crypto self-test (R4A-3), opening the persistent state
// store (internal/store), establishing the trust root (first boot vs. an
// RPM-shipped update vs. the persisted root, architecture doc section
// 7.6/7.7's forward-only chaining), and the resulting TAMPERED/first-boot
// decision — stopping short of relayd's actual main() wiring (control
// stream, Tetragon socket, telemetry), which is step 6 scope.
package agent
