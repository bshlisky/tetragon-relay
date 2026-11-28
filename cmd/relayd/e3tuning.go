//go:build !testca

package main

import (
	"github.com/bshlisky/tetragon-relay/internal/agent"
	"github.com/bshlisky/tetragon-relay/internal/tetra"
)

// e3Tuning is the identity outside the testca (E3) build: production
// relayd takes no tuning from its environment.
func e3Tuning(_ agent.Auditor, tc tetra.Config) (tetra.Config, int) { return tc, 0 }
