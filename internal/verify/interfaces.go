package verify

// EpochSource provides the current epoch for a scope, as tracked by the
// agent's persistent state (internal/store, a later step). An error from
// Current must always result in rejection; it must never be treated as "no
// prior epoch, so accept."
type EpochSource interface {
	Current(scope string) (uint64, error)
}

// Guardrails checks a parsed, otherwise-valid set of policies against the
// agent-compiled safety rules of architecture doc section 7.5 (e.g. no
// Sigkill/Override on sshd, systemd, Tetragon itself, etc.). It is called
// last, only after every other check has passed, and only with policies
// that have already been schema- and hash-validated.
//
// The real implementation is step 2 of this project. Tests in this step use
// a fake that records its calls.
type Guardrails interface {
	Check(policies []Policy) error
}
