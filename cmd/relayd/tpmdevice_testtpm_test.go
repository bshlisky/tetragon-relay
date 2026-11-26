//go:build testtpm

package main

import "testing"

func TestParseTCPTPMSpec(t *testing.T) {
	cfg, err := parseTCPTPMSpec("127.0.0.1:12321,127.0.0.1:12322")
	if err != nil {
		t.Fatalf("parseTCPTPMSpec: %v", err)
	}
	if cfg.CommandAddress != "127.0.0.1:12321" || cfg.PlatformAddress != "127.0.0.1:12322" {
		t.Fatalf("parseTCPTPMSpec = %+v", cfg)
	}
	for _, bad := range []string{"", "127.0.0.1:12321", "127.0.0.1:12321,", ",127.0.0.1:12322", "a,b,c"} {
		if _, err := parseTCPTPMSpec(bad); err == nil {
			t.Errorf("parseTCPTPMSpec(%q) = nil error, want rejection", bad)
		}
	}
}
