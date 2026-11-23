//go:build linux

package hostprobe

import "testing"

func TestCurrentBootID_Linux(t *testing.T) {
	restore := bootIDPath
	defer func() { bootIDPath = restore }()

	t.Run("real_path", func(t *testing.T) {
		bootIDPath = restore
		id, err := CurrentBootID()
		if err != nil {
			t.Fatalf("CurrentBootID: %v", err)
		}
		if id == "" {
			t.Fatal("CurrentBootID returned an empty string")
		}
	})

	t.Run("missing_path", func(t *testing.T) {
		bootIDPath = "/this/path/does/not/exist"
		if _, err := CurrentBootID(); err == nil {
			t.Fatal("CurrentBootID with a nonexistent path returned no error")
		}
	})
}
