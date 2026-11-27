package store_test

import (
	"errors"
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/apply"
	"github.com/bshlisky/tetragon-relay/internal/store"
)

func monitorSet() apply.LKGSet {
	return apply.LKGSet{Mode: "monitor", RawEnvelope: []byte("env"), RootVersion: 1, Policies: []apply.LKGPolicy{
		{Name: "block-shadow-read", Version: 1, CanonicalJSON: []byte(`{"name":"block-shadow-read"}`)},
	}}
}

func TestCommitApplied_PersistsAllPartsInOneGeneration(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	s, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	gen := s.Generation()
	if err := s.CommitApplied(store.AppliedCommit{Domain: "relay", Set: monitorSet(), Scope: "prod-db", Epoch: 2, MonitorNames: []string{"block-shadow-read", "block-shadow-read"}}); err != nil {
		t.Fatalf("CommitApplied: %v", err)
	}
	if got := s.Generation(); got != gen+1 {
		t.Fatalf("Generation = %d, want exactly one new generation (%d)", got, gen+1)
	}
	// A second monitor commit with an already-recorded name must not duplicate it.
	if err := s.CommitApplied(store.AppliedCommit{Domain: "relay", Set: monitorSet(), Scope: "prod-db", Epoch: 3, MonitorNames: []string{"block-shadow-read", "other"}}); err != nil {
		t.Fatalf("second CommitApplied: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if e, err := s2.Current("prod-db"); err != nil || e != 3 {
		t.Fatalf("Current = %d, %v; want 3", e, err)
	}
	for _, name := range []string{"block-shadow-read", "other"} {
		if seen, err := s2.SeenInMonitor("prod-db", name); err != nil || !seen {
			t.Fatalf("SeenInMonitor(%q) = %v, %v; want true", name, seen, err)
		}
	}
	got, ok := s2.Get("relay")
	if !ok || got.Mode != "monitor" || got.RootVersion != 1 || string(got.RawEnvelope) != "env" {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
}

func TestCommitApplied_Rejections(t *testing.T) {
	s, _, _ := newTestStore(t)
	if err := s.RecordEpoch("prod-db", 5); err != nil {
		t.Fatal(err)
	}
	gen := s.Generation()
	enforce := monitorSet()
	enforce.Mode = "enforce"
	cases := map[string]store.AppliedCommit{
		"no domain":             {Set: monitorSet(), Scope: "prod-db", Epoch: 6},
		"no scope":              {Domain: "relay", Set: monitorSet(), Epoch: 6},
		"epoch not greater":     {Domain: "relay", Set: monitorSet(), Scope: "prod-db", Epoch: 5},
		"monitor names enforce": {Domain: "relay", Set: enforce, Scope: "prod-db", Epoch: 6, MonitorNames: []string{"x"}},
	}
	for name, c := range cases {
		if err := s.CommitApplied(c); err == nil {
			t.Errorf("%s: CommitApplied = nil, want rejection", name)
		}
	}
	if s.Generation() != gen {
		t.Fatalf("a rejected CommitApplied changed the generation")
	}
	if seen, _ := s.SeenInMonitor("prod-db", "x"); seen {
		t.Fatal("rejected commit recorded monitor history")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitApplied(store.AppliedCommit{Domain: "relay", Set: monitorSet(), Scope: "prod-db", Epoch: 9}); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("CommitApplied on a closed store = %v, want ErrClosed", err)
	}
}
