// Package testvectors defines the on-disk shape of the JSON test vectors
// under testdata/vectors/ and loads them. It is shared by the
// `testtools`-tagged generator (cmd/bundlesign-test) and the ordinary
// _test.go files in internal/trust and internal/verify, so the schema used
// to write a vector and the schema used to read it back can never silently
// diverge.
//
// This package carries no cryptographic logic of its own: it is pure data
// shape plus JSON (de)serialization.
package testvectors
