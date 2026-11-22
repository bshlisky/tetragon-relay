package testvectors

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Kind discriminates what a Vector exercises.
type Kind string

const (
	// KindVerify exercises internal/verify.Verify end to end: load
	// RootMetadataB64 with trust.LoadInitialRoot, obtain a targets
	// Verifier at Now (treating an expired-root error as "no verifier
	// available"), then call verify.Verify on EnvelopeB64 and compare
	// the result code against ExpectedResult.
	KindVerify Kind = "verify"

	// KindTrustLoad exercises trust.LoadInitialRoot(RootMetadataB64)
	// directly and compares the returned error against ExpectedError
	// (using errors.Is against a fixed name->error map maintained by the
	// test, not by this package).
	KindTrustLoad Kind = "trust_load"

	// KindTrustUpdate exercises
	// trust.LoadInitialRoot(RootMetadataB64).Update(NewRootMetadataB64, Now)
	// and compares the returned error against ExpectedError.
	KindTrustUpdate Kind = "trust_update"
)

// Vector is one test case, serialized to its own JSON file under
// testdata/vectors/.
type Vector struct {
	Name        string `json:"name"`
	Kind        Kind   `json:"kind"`
	Description string `json:"description"`

	// RootMetadataB64 is the initial/current trust root DSSE envelope,
	// base64 of the raw envelope JSON bytes.
	RootMetadataB64 string `json:"root_metadata_b64,omitempty"`
	// NewRootMetadataB64 is the candidate next root version, for
	// KindTrustUpdate only.
	NewRootMetadataB64 string `json:"new_root_metadata_b64,omitempty"`
	// EnvelopeB64 is the signed policy bundle DSSE envelope, for
	// KindVerify only.
	EnvelopeB64 string `json:"envelope_b64,omitempty"`

	HostUUID        string   `json:"host_uuid,omitempty"`
	AllowedScopes   []string `json:"allowed_scopes,omitempty"`
	TetragonVersion string   `json:"tetragon_version,omitempty"`
	CurrentEpoch    uint64   `json:"current_epoch"`

	// Now is RFC3339 and is the time the vector must be evaluated at.
	Now string `json:"now"`

	// ExpectedResult is the verify.Code string (e.g. "ACCEPT",
	// "REJECTED_SIGNATURE"), for KindVerify.
	ExpectedResult string `json:"expected_result,omitempty"`
	// ExpectedError names a trust package sentinel error (e.g.
	// "ErrVersionRollback"), for KindTrustLoad / KindTrustUpdate.
	ExpectedError string `json:"expected_error,omitempty"`
}

// Save writes v as pretty-printed JSON to <dir>/<v.Name>.json.
func Save(dir string, v Vector) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(filepath.Join(dir, v.Name+".json"), data, 0o600)
}

// Load reads and parses one vector file. path is always either a fixed,
// repo-relative testdata path supplied by test/generator code, or a file
// name returned by LoadDir's own os.ReadDir call; it is never derived from
// untrusted input, so the variable file path is not a traversal risk here.
func Load(path string) (Vector, error) {
	data, err := os.ReadFile(path) //nolint:gosec // see doc comment above
	if err != nil {
		return Vector{}, err
	}
	var v Vector
	if err := json.Unmarshal(data, &v); err != nil {
		return Vector{}, err
	}
	return v, nil
}

// LoadDir reads every *.json file directly inside dir as a Vector, sorted by
// file name.
func LoadDir(dir string) ([]Vector, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var vectors []Vector
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		v, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		vectors = append(vectors, v)
	}
	return vectors, nil
}
