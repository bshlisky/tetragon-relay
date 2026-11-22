package strictjson

import "errors"

// Sentinel errors returned by this package. Callers should use errors.Is.
var (
	// ErrDuplicateKey is returned when the same object key appears twice
	// at the same nesting level.
	ErrDuplicateKey = errors.New("strictjson: duplicate object key")

	// ErrMaxDepthExceeded is returned when object/array nesting exceeds
	// the configured maximum depth.
	ErrMaxDepthExceeded = errors.New("strictjson: maximum nesting depth exceeded")

	// ErrInvalidUTF8 is returned when the input is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("strictjson: input is not valid UTF-8")

	// ErrTrailingData is returned when bytes remain after the top-level
	// JSON value.
	ErrTrailingData = errors.New("strictjson: trailing data after JSON value")

	// ErrNotSingleValue is returned when the input contains no JSON value
	// at all.
	ErrNotSingleValue = errors.New("strictjson: input does not contain exactly one JSON value")
)
