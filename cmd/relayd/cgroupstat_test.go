package main

import "testing"

func TestCgroupV2Path(t *testing.T) {
	p, err := cgroupV2Path([]byte("12:cpu:/x\n0::/system.slice/tetragon-relay.service\n"))
	if err != nil || p != "/system.slice/tetragon-relay.service" {
		t.Fatalf("p=%q err=%v", p, err)
	}
	if _, err := cgroupV2Path([]byte("12:cpu:/x\n")); err == nil {
		t.Fatal("accepted a v1-only file")
	}
	if p, err := cgroupV2Path([]byte("0::/../../etc\n")); err != nil || p != "/etc" {
		t.Fatalf("p=%q err=%v", p, err)
	}
}

func TestParseCPUStat(t *testing.T) {
	u, th, err := parseCPUStat([]byte("usage_usec 123\nuser_usec 100\nnr_periods 9\nnr_throttled 4\nthrottled_usec 77\nbad line here\nx y\n"))
	if err != nil || u != 123 || th != 4 {
		t.Fatalf("u=%d th=%d err=%v", u, th, err)
	}
	if _, _, err := parseCPUStat([]byte("usage_usec 1\n")); err == nil {
		t.Fatal("accepted a cpu.stat without nr_throttled")
	}
}
