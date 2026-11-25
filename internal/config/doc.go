// Package config implements docs/prompts/step-06a.md Part B: loading and
// validating relayd's static configuration file, /etc/tetragon-relay/
// relay.yaml (architecture doc section 8.5/8.6), whose path is given by
// the --config flag (cmd/relayd, Part C).
//
// Load refuses to read the file at all unless it is a regular file (never
// a symlink), owned by root, group tetragon-relay, with mode no more
// permissive than 0640 -- the ownership and mode architecture doc 8.5's
// filesystem table requires. Parsing reuses internal/yamlharden's hardened
// YAML ingestion (the same rules internal/policydoc applies to policy
// YAML), so relay.yaml is subject to the identical anchor/alias/tag/
// ambiguous-scalar/control-character rejections before any value in it is
// trusted. The schema is closed: any key relay.yaml contains that this
// package's schema does not know about is a load error, never silently
// ignored.
//
// Every required field (host.uuid, host.allowed_scopes, the controller
// and collector endpoints and SPIFFE IDs, identity's trust domain and
// enrollment trust bundle path, the Tetragon socket path and persist
// directory) has no default: an absent or empty value is a typed load
// error. Every other field's zero or absent value is the secure
// behavior; the one field that can relax a security check
// (tetragon.allow_selinux_disabled) requires an explicit "true" to do so,
// and Config.SecurityRelaxations reports it so relayd's startup sequence
// (internal/agent, Part C) can write a loud audit record before
// proceeding.
//
// Config.Digest is the SHA-256 of the exact bytes Load read, unmodified
// by parsing or defaulting -- the value that goes into Hello.config_digest
// (architecture doc 6.2).
package config
