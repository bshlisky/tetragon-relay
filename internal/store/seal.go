package store

// KeySealer provides the HMAC key this package uses to authenticate the
// index file (step-04b.md Part C4). A fake now (FakeKeySealer); a
// TPM-sealed key bound to PCR 7 in step 5 (architecture doc section 8.10).
type KeySealer interface {
	// Unseal returns the HMAC key. Called once per Open and once per
	// Save; a real TPM-backed implementation may re-derive it each
	// time rather than caching it in process memory.
	Unseal() ([]byte, error)
}

// FakeKeySealer is an in-memory KeySealer: it always returns the same,
// caller-supplied key. Tests construct one with a fixed key so that
// closing and re-opening a Store against the same directory (simulating
// an agent restart) uses the same key, exactly as a real TPM seal would
// for an unchanged PCR 7.
type FakeKeySealer struct {
	Key []byte
	// Err, if set, is returned by Unseal instead of Key (simulating the
	// TPM not being ready).
	Err error
}

// Unseal implements KeySealer.
func (f *FakeKeySealer) Unseal() ([]byte, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Key, nil
}
