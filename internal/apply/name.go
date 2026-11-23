package apply

import (
	"crypto/sha256"
	"fmt"
	"regexp"

	"github.com/bshlisky/tetragon-relay/internal/limits"
)

// RelayDomain is the "domain" (sensors.proto's AddTracingPolicyRequest.
// domain/ListTracingPoliciesRequest.domain/TracingPolicyStatus.domain,
// pkg/server/server.go:250-258) this engine uses as its relay-managed
// marker (step 3 prompt Part D1; ADR 0016). Every policy this engine loads
// carries this domain; only policies with both this domain AND a loaded
// name matching loadedNamePattern are ever candidates for deletion.
const RelayDomain = "relay-managed"

// loadedNamePattern is "<name>-v<version>-<8 lowercase hex>", where <name>
// already satisfies limits.PolicyNamePattern. ADR 0016 shows this is
// always both a valid Tetragon v1.8.0 loaded name (RFC 1123 DNS
// subdomain) and well under its 253-byte limit.
var loadedNamePattern = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)-v([0-9]+)-([0-9a-f]{8})$`)

// LoadedName implements step 3 prompt Part D1: the name under which a
// bundle policy is actually loaded into Tetragon.
func LoadedName(policyName string, version int, canonicalJSON []byte) (string, error) {
	if !limits.PolicyNamePattern.MatchString(policyName) {
		return "", fmt.Errorf("apply: %q is not a valid policy name", policyName)
	}
	if version < limits.MinPolicyVersion || version > limits.MaxPolicyVersion {
		return "", fmt.Errorf("apply: version %d out of range", version)
	}
	sum := sha256.Sum256(canonicalJSON)
	hexPrefix := fmt.Sprintf("%x", sum)[:8]
	name := fmt.Sprintf("%s-v%d-%s", policyName, version, hexPrefix)
	if len(name) > limits.MaxLoadedPolicyNameBytes {
		// Not reachable given the bounds above (ADR 0016), but checked
		// explicitly rather than trusted, per this project's "defensive
		// invariant" convention.
		return "", fmt.Errorf("apply: loaded name %q exceeds %d bytes", name, limits.MaxLoadedPolicyNameBytes)
	}
	if !loadedNamePattern.MatchString(name) {
		return "", fmt.Errorf("apply: computed loaded name %q does not match the expected pattern", name)
	}
	return name, nil
}

// parseLoadedName is LoadedName's inverse, used when deciding whether an
// already-loaded Tetragon policy is a candidate this engine is allowed to
// touch (Part D1: "Only policies whose names match this pattern AND carry
// a relay-managed marker... are ever deleted"). ok is false for any name
// that does not match the pattern at all (every foreign/manually-loaded
// policy, and anything with a syntactically invalid version/hash).
func parseLoadedName(name string) (policyName string, version int, hexPrefix string, ok bool) {
	m := loadedNamePattern.FindStringSubmatch(name)
	if m == nil {
		return "", 0, "", false
	}
	var v int
	if _, err := fmt.Sscanf(m[3], "%d", &v); err != nil {
		return "", 0, "", false
	}
	return m[1], v, m[4], true
}

// isRelayManaged implements Part D1's "foreign policies are never touched"
// rule: both the loaded name must match loadedNamePattern AND the
// policy's domain must be RelayDomain.
func isRelayManaged(name, domain string) bool {
	if domain != RelayDomain {
		return false
	}
	_, _, _, ok := parseLoadedName(name)
	return ok
}
