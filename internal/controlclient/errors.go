package controlclient

import (
	"errors"

	"github.com/bshlisky/tetragon-relay/internal/spiffetls"
)

var (
	// ErrControllerSPIFFEIDMismatch is returned (wrapped) by
	// BuildTLSConfig's VerifyConnection when the server certificate's
	// URI SAN does not exactly equal the configured controller SPIFFE
	// ID (architecture doc 6.1: "SPIFFE ID pinning, not hostname").
	// It is spiffetls.ErrServerSPIFFEIDMismatch (ADR 0039 section 8).
	ErrControllerSPIFFEIDMismatch = spiffetls.ErrServerSPIFFEIDMismatch

	// ErrDialCanceled is returned by Dial when ctx is canceled before any
	// endpoint became ready.
	ErrDialCanceled = errors.New("controlclient: dial canceled before any endpoint became ready")
)
