//go:build !testca

package main

import (
	"context"

	"github.com/bshlisky/tetragon-relay/internal/agent"
)

// startE3Profiler is a no-op outside the testca (E3) build: production
// relayd never writes profiles.
func startE3Profiler(context.Context, agent.Auditor) {}
