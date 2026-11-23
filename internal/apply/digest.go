package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

// Digest implements step 3 prompt Part D8 / architecture doc section 6.4:
// ListTracingPolicies (sensors.proto:131-160, TracingPolicyStatus) does not
// return policy content, so the loaded-policy digest is computed over the
// sorted (loaded name, state, enabled, mode, sensors) tuples it does
// return, for every relay-managed policy in statuses. Since the loaded
// name embeds CanonicalSHA256's first 8 hex (Part D1), content identity is
// still bound to this digest (see docs/decisions/0017-loaded-policy-digest-residual-risk.md
// for the residual risk this does not cover).
func Digest(statuses []tetra.TracingPolicyStatus) string {
	var lines []string
	for _, s := range statuses {
		if !isRelayManaged(s.Name, s.Domain) {
			continue
		}
		sensors := append([]string(nil), s.Sensors...)
		sort.Strings(sensors)
		lines = append(lines, fmt.Sprintf("%s|%s|%t|%s|%s", s.Name, s.State.String(), s.Enabled, s.Mode.String(), strings.Join(sensors, ",")))
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}
