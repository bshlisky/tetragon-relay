package hostprobe

import (
	"encoding/json"
	"testing"
)

// FuzzHostFacts fuzzes Parse (step 3 prompt Part E6): the JSON file parser
// must never panic or hang on arbitrary input, and a successfully parsed
// document must round-trip (re-marshal, re-parse, same fields) since
// HostFacts has no custom marshaling to introduce asymmetry.
func FuzzHostFacts(f *testing.F) {
	seed := validFacts("boot-a")
	data, _ := json.Marshal(seed)
	f.Add(data)
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte(`{"schema_version":1,"boot_id":"x","boot_id":"y"}`))
	f.Add([]byte(`{"schema_version":"not-a-number"}`))
	f.Add([]byte(`{"schema_version":1,"error_injection_list":[1,2,3]}`))
	f.Add([]byte(`not json at all`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := Parse(raw)
		if err != nil {
			if got != nil {
				t.Fatalf("non-nil HostFacts alongside error %v", err)
			}
			return
		}
		again, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("re-marshal accepted HostFacts: %v", err)
		}
		reparsed, err := Parse(again)
		if err != nil {
			t.Fatalf("re-marshaled HostFacts did not re-parse: %v", err)
		}
		if reparsed.SchemaVersion != got.SchemaVersion || reparsed.BootID != got.BootID {
			t.Fatalf("round-trip mismatch: %+v vs %+v", got, reparsed)
		}
	})
}
