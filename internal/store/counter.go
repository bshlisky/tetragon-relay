package store

import "sync"

// MonotonicCounter mirrors the store index's generation number outside the
// store directory itself, so an attacker who restores an old (but validly
// HMAC'd, since it was genuinely produced by this agent at the time)
// backup of the store directory cannot roll it back (step-04b.md Part C5).
// A fake now (FakeMonotonicCounter); a TPM NV counter in step 5
// (architecture doc section 8.10).
type MonotonicCounter interface {
	// Read returns the counter's current value.
	Read() (uint64, error)
	// Increment atomically adds one to the counter and returns the new
	// value. It must be safe to call Increment more than once in a row
	// with no intervening Read (Open's crash-window recovery does
	// exactly that).
	Increment() (uint64, error)
}

// FakeMonotonicCounter is an in-memory MonotonicCounter. Tests construct
// one value and pass it across repeated Open/Close calls against the same
// directory to simulate a TPM NV counter surviving an agent restart (a
// value scoped to a single Open call, by contrast, would not catch a
// rollback test at all).
type FakeMonotonicCounter struct {
	mu    sync.Mutex
	value uint64
}

// NewFakeMonotonicCounter returns a FakeMonotonicCounter starting at 0
// (matching a freshly-provisioned TPM NV counter before first boot).
func NewFakeMonotonicCounter() *FakeMonotonicCounter {
	return &FakeMonotonicCounter{}
}

// Read implements MonotonicCounter.
func (c *FakeMonotonicCounter) Read() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value, nil
}

// Increment implements MonotonicCounter.
func (c *FakeMonotonicCounter) Increment() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value++
	return c.value, nil
}

// Set forces the counter to an exact value, for tests constructing a
// specific rollback/skip scenario directly rather than via a sequence of
// real Opens.
func (c *FakeMonotonicCounter) Set(v uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value = v
}
