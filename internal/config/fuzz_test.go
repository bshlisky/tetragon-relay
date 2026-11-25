package config

import "testing"

// FuzzConfig fuzzes parse directly on raw YAML bytes (Part B5), bypassing
// Load's filesystem checks the same way policydoc.FuzzPolicyParse bypasses
// nothing filesystem-related (it has none) -- the only interesting
// property is "never panic or hang", matching this project's other
// parser fuzz targets (FuzzPolicyParse, FuzzRootUpdate, FuzzStrictJSON,
// FuzzStoreIndex).
func FuzzConfig(f *testing.F) {
	f.Add([]byte(validYAML))
	f.Add([]byte(""))
	f.Add([]byte("not: valid: yaml: ["))
	f.Add([]byte("- a\n- b\n"))
	f.Add([]byte("host: &a\n  uuid: x\ncontroller: *a\n"))
	f.Add([]byte("host:\n  uuid: \"9b2f1a30-1111-4b2a-8c3d-0123456789ab\"\n  allowed_scopes: [\"x\"]\nunknown: 1\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parse(data)
	})
}
