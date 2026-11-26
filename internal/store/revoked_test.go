package store_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bshlisky/tetragon-relay/internal/limits"
	"github.com/bshlisky/tetragon-relay/internal/store"
)

// ADR 0035 / docs/reviews/step-06a-e3-decisions.md D2.

func TestRevocation_PersistsAcrossReopen(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	s, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok, err := s.Revocation(); err != nil || ok {
		t.Fatalf("Revocation() on a fresh store = ok %v, err %v; want none", ok, err)
	}
	at := time.Date(2026, 11, 26, 16, 44, 12, 0, time.UTC)
	if err := s.MarkRevoked(at, "REVOKED: e3controller"); err != nil {
		t.Fatalf("MarkRevoked: %v", err)
	}
	// First marker wins.
	if err := s.MarkRevoked(at.Add(time.Hour), "second"); err != nil {
		t.Fatalf("second MarkRevoked: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	r, ok, err := s2.Revocation()
	if err != nil || !ok {
		t.Fatalf("Revocation() after reopen = ok %v, err %v; want the marker", ok, err)
	}
	if !r.At.Equal(at) || r.Reason != "REVOKED: e3controller" {
		t.Fatalf("Revocation() = %+v", r)
	}

	if err := s2.ClearRevocation(); err != nil {
		t.Fatalf("ClearRevocation: %v", err)
	}
	if _, ok, _ := s2.Revocation(); ok {
		t.Fatal("marker still present after ClearRevocation")
	}
	if err := s2.ClearRevocation(); err != nil {
		t.Fatalf("ClearRevocation with no marker: %v", err)
	}
}

func TestRevocation_CoveredByHMAC(t *testing.T) {
	dir, sealer, counter := setupTamperable(t)
	s, err := store.Open(dir, sealer, counter)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkRevoked(time.Unix(1, 0), "REVOKED: abc"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw := readIndexBytes(t, dir)
	edited := bytes.Replace(raw, []byte("REVOKED: abc"), []byte("REVOKED: xyz"), 1)
	if bytes.Equal(raw, edited) {
		t.Fatal("reason not found in the index file")
	}
	writeIndexBytes(t, dir, edited)
	reopenExpectTampered(t, dir, sealer, counter)
}

func TestRevocation_RejectsInvalidInput(t *testing.T) {
	s, _, _ := newTestStore(t)
	if err := s.MarkRevoked(time.Time{}, "x"); err == nil {
		t.Fatal("MarkRevoked with a zero time succeeded")
	}
	long := strings.Repeat("a", limits.MaxRevokedReasonBytes+1)
	if err := s.MarkRevoked(time.Unix(1, 0), long); !errors.Is(err, store.ErrLimitExceeded) {
		t.Fatalf("MarkRevoked(long reason) = %v, want ErrLimitExceeded", err)
	}
	if _, ok, _ := s.Revocation(); ok {
		t.Fatal("a rejected MarkRevoked left a marker")
	}
}

func TestRevocation_ClosedStore(t *testing.T) {
	s, _, _ := newTestStore(t)
	_ = s.Close()
	if _, _, err := s.Revocation(); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("Revocation() on closed store = %v, want ErrClosed", err)
	}
	if err := s.MarkRevoked(time.Unix(1, 0), "x"); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("MarkRevoked on closed store = %v, want ErrClosed", err)
	}
	if err := s.ClearRevocation(); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("ClearRevocation on closed store = %v, want ErrClosed", err)
	}
}
