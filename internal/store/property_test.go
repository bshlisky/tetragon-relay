package store

import (
	"errors"
	"math/rand"
	"os"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/apply"
)

// This file is step-04b.md Part E4: a property test over random
// SEQUENCES combining every write operation (apply/Put, epoch, history,
// trust) with random crash points and reopens, asserting that across the
// whole run epochs and root versions are never observed to go backward,
// and that a domain's LKG never ends up referencing a root version this
// package can no longer produce (ADR 0025's retention invariant), no
// matter which combination of operations a crash happened to land in the
// middle of. This complements fault_matrix_test.go's per-operation sweep
// (every crash point of ONE operation type in isolation) with randomized,
// multi-operation-type sequences, which can exercise interactions
// (e.g. a crash during PersistTrustRoot immediately followed by a Put
// referencing the version that may or may not have survived) the
// deterministic single-operation matrix does not.

// propertySeeds are run as separate subtests so a failure is
// reproducible (the seed is printed) without needing -count or external
// state, while still covering several independent random walks.
var propertySeeds = []int64{1, 2, 3, 4, 5}

func TestProperty_RandomOperationSequence(t *testing.T) {
	for _, seed := range propertySeeds {
		t.Run(itoa(int(seed)), func(t *testing.T) {
			runPropertySequence(t, seed)
		})
	}
}

func runPropertySequence(t *testing.T, seed int64) {
	t.Helper()
	const iterations = 150
	const scopeCount = 3
	const domainCount = 2

	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test PRNG, not a security use

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	counter := NewFakeMonotonicCounter()
	sealer := newTestSealer()

	s, err := Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("initial Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	scopes := make([]string, scopeCount)
	for i := range scopes {
		scopes[i] = "scope-" + itoa(i)
	}
	domains := make([]string, domainCount)
	for i := range domains {
		domains[i] = "domain-" + itoa(i)
	}

	nextEpoch := make(map[string]uint64, scopeCount)
	for _, sc := range scopes {
		nextEpoch[sc] = 1
	}
	var nextRootVersion uint64 = 1
	var lastPersistedRootVersion uint64 // 0 = none yet

	// lastSeenEpoch/lastSeenRootVersion track the highest value this test
	// has ever observed via a successful read, for the monotonicity
	// assertion below: a later read must never report something LOWER
	// than a value already confirmed durable.
	lastSeenEpoch := make(map[string]uint64, scopeCount)
	var lastSeenRootVersion uint64

	checkInvariants := func(st *Store) {
		for _, sc := range scopes {
			e, err := st.Current(sc)
			if err != nil {
				t.Fatalf("Current(%s): %v", sc, err)
			}
			if e < lastSeenEpoch[sc] {
				t.Fatalf("scope %s: epoch went backward: saw %d after previously observing %d", sc, e, lastSeenEpoch[sc])
			}
			lastSeenEpoch[sc] = e
		}
		if _, version, ok, err := st.TrustRoot(); err != nil {
			t.Fatalf("TrustRoot: %v", err)
		} else if ok {
			if version < lastSeenRootVersion {
				t.Fatalf("root version went backward: saw %d after previously observing %d", version, lastSeenRootVersion)
			}
			lastSeenRootVersion = version
		}
		for _, d := range domains {
			set, ok := st.Get(d)
			if !ok {
				continue
			}
			if set.RootVersion == 0 {
				continue
			}
			if _, ok, err := st.RootAtVersion(set.RootVersion); err != nil {
				t.Fatalf("RootAtVersion(%d) for domain %s's own recorded version: %v", set.RootVersion, d, err)
			} else if !ok {
				t.Fatalf("domain %s references root version %d, but it is no longer retained (ADR 0025 retention invariant violated)", d, set.RootVersion)
			}
		}
	}

	for i := 0; i < iterations; i++ {
		crashAfter := -1 // -1 means "do not crash this iteration"
		if rng.Intn(3) == 0 {
			crashAfter = rng.Intn(10) // generously above any single op's FS-call count
		}

		var action func(st *Store) error
		switch rng.Intn(3) {
		case 0:
			scope := scopes[rng.Intn(len(scopes))]
			e := nextEpoch[scope]
			nextEpoch[scope] = e + 1
			action = func(st *Store) error { return st.RecordEpoch(scope, e) }
		case 1:
			domain := domains[rng.Intn(len(domains))]
			// Reference the last root version actually known to be
			// persisted (0 if none yet) -- Put itself does not require
			// a root to already exist, matching production, where an
			// LKG is only ever persisted with a RootVersion that came
			// from a real verify.Result.
			rv := lastPersistedRootVersion
			action = func(st *Store) error {
				return st.Put(domain, apply.LKGSet{Mode: "enforce", RawEnvelope: []byte("env"), RootVersion: rv})
			}
		case 2:
			v := nextRootVersion
			nextRootVersion = v + 1
			action = func(st *Store) error {
				err := st.PersistTrustRoot([]byte("root-bytes-"+itoa(int(v))), v)
				if err == nil {
					lastPersistedRootVersion = v
				}
				return err
			}
		}

		if crashAfter < 0 {
			if err := action(s); err != nil {
				t.Fatalf("iteration %d: action failed without any injected crash: %v", i, err)
			}
			checkInvariants(s)
			continue
		}

		// Inject a crash: swap in a faulting FS for this action only, let
		// the (expected) error happen, close (releasing the lock as a
		// crashed process's exit would), then reopen with a clean FS and
		// the SAME counter (simulating the TPM NV counter surviving a
		// real restart) to recover.
		s.fs = newFaultFS(OSFS{}, crashAfter)
		actionErr := action(s)
		_ = s.Close()
		if actionErr != nil &&
			!errors.As(actionErr, new(errSimulatedCrash)) &&
			!errors.Is(actionErr, ErrLimitExceeded) &&
			!errors.Is(actionErr, ErrCommittedCounterLag) {
			t.Fatalf("iteration %d: action returned a non-simulated-crash error: %v", i, actionErr)
		}

		reopened, err := Open(dir, sealer, counter)
		if err != nil {
			t.Fatalf("iteration %d: recovery Open after crashAfter=%d (action err=%v): %v", i, crashAfter, actionErr, err)
		}
		if reopened.FirstBoot() {
			t.Fatalf("iteration %d: recovery Open reported FirstBoot after a mid-run crash, want false", i)
		}
		checkInvariants(reopened)
		s = reopened

		// A crash's real on-disk outcome is "old or new," chosen by
		// exactly where the simulated fault landed, not by whether this
		// test's own action() closure happened to return a nil error:
		// the new generation's rename+dir-fsync can have already
		// completed on disk before the fault lands on a later step this
		// test still counts as part of the "same" action. Resync every
		// piece of this test's own bookkeeping from the real,
		// just-reopened state, rather than trusting "did action() return
		// nil" to mean "did it take effect" -- otherwise a later
		// iteration could reference an already-superseded (and so
		// already garbage-collected) root version purely because this
		// test's OWN model fell behind reality, which would be a false
		// positive, not evidence of a real retention bug.
		if _, version, ok, err := s.TrustRoot(); err != nil {
			t.Fatalf("iteration %d: resync TrustRoot: %v", i, err)
		} else if ok {
			lastPersistedRootVersion = version
			if nextRootVersion <= version {
				nextRootVersion = version + 1
			}
		}
		for _, sc := range scopes {
			e, err := s.Current(sc)
			if err != nil {
				t.Fatalf("iteration %d: resync Current(%s): %v", i, sc, err)
			}
			if nextEpoch[sc] <= e {
				nextEpoch[sc] = e + 1
			}
		}
	}
}
