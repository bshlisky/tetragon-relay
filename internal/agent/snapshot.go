package agent

import (
	"context"
	"fmt"

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
	snap, err := tetragonSnapshot(ctx, p.Client)
	if err != nil {
		return StateSnapshot{}, err
	}
	epochs := make(map[string]uint64, len(p.Scopes))
	for _, scope := range p.Scopes {
		e, err := p.Store.Current(scope)
		if err != nil {
			return StateSnapshot{}, fmt.Errorf("agent: snapshot: current epoch for %q: %w", scope, err)
		}
		epochs[scope] = e
	}
	snap.Epochs = epochs
	return snap, nil
}
