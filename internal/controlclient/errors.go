package controlclient

import "errors"

var (
	// ErrControllerSPIFFEIDMismatch is returned (wrapped) by
	// BuildTLSConfig's VerifyConnection when the server certificate's
	// URI SAN does not exactly equal the configured controller SPIFFE
	// ID (architecture doc 6.1: "SPIFFE ID pinning, not hostname").
	ErrControllerSPIFFEIDMismatch = errors.New("controlclient: server certificate's SPIFFE ID does not match the configured controller SPIFFE ID")

	// ErrDialCanceled is returned by Dial when ctx is canceled before any
	// endpoint became ready.
	ErrDialCanceled = errors.New("controlclient: dial canceled before any endpoint became ready")
)
