package agent

import (
	"context"
	"encoding/hex"
	"fmt"

	controlv1 "github.com/bshlisky/tetragon-relay/api/relay/control/v1"
	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

// snapshotTetragonClient is the subset of *tetra.Client RealSnapshotProvider
// needs, so it can be tested without a real Tetragon socket.
// *tetra.Client satisfies it directly.
type snapshotTetragonClient interface {
	ListTracingPolicies(ctx context.Context, domain string) ([]tetra.TracingPolicyStatus, error)
}

var _ snapshotTetragonClient = (*tetra.Client)(nil)

// RealSnapshotProvider implements SnapshotProvider from a real store and
// Tetragon connection (relayd's production wiring, Part C). Scopes is
// every scope this host serves (relay.yaml's host.allowed_scopes,
// architecture doc 8.6), used to fill Hello/Heartbeat/StateReport's
// per-scope epoch map.
type RealSnapshotProvider struct {
	Store  *store.Store
	Client snapshotTetragonClient
	Scopes []string
}

// Snapshot implements SnapshotProvider.
func (p *RealSnapshotProvider) Snapshot(ctx context.Context) (StateSnapshot, error) {
	statuses, err := p.Client.ListTracingPolicies(ctx, "")
	if err != nil {
		return StateSnapshot{}, fmt.Errorf("agent: snapshot: ListTracingPolicies: %w", err)
	}
	// architecture doc 6.4's loaded-policy digest, computed from
	// Tetragon's own view (apply.Digest, step 3 prompt Part D8; see
	// docs/decisions/0017-loaded-policy-digest-residual-risk.md for the
	// documented gap between this and the architecture doc's literal
	// algorithm).
	digest, err := hex.DecodeString(apply.Digest(statuses))
	if err != nil {
		return StateSnapshot{}, fmt.Errorf("agent: snapshot: decode digest: %w", err)
	}

	epochs := make(map[string]uint64, len(p.Scopes))
	for _, scope := range p.Scopes {
		e, err := p.Store.Current(scope)
		if err != nil {
			return StateSnapshot{}, fmt.Errorf("agent: snapshot: current epoch for %q: %w", scope, err)
		}
		epochs[scope] = e
	}

	policies := make([]*controlv1.LoadedPolicy, 0, len(statuses))
	for _, s := range statuses {
		policies = append(policies, &controlv1.LoadedPolicy{
			Name:    s.Name,
			State:   s.State.String(),
			Enabled: s.Enabled,
		})
	}

	return StateSnapshot{
		Epochs:       epochs,
		LoadedDigest: digest,
		Policies:     policies,
		Health:       &controlv1.TetragonHealth{Serving: true},
	}, nil
}
