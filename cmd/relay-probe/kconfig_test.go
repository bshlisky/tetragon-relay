package main

import (
	"strings"
	"testing"
)

func TestParseKconfig(t *testing.T) {
	data := `
# comment
CONFIG_BPF_KPROBE_OVERRIDE=y
CONFIG_FUNCTION_ERROR_INJECTION=y
# CONFIG_BPF_LSM is not set
CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_SOMETHING=m
not a config line
`
	cfg := parseKconfig(strings.NewReader(data))
	if !kconfigSet(cfg, "CONFIG_BPF_KPROBE_OVERRIDE") {
		t.Error("CONFIG_BPF_KPROBE_OVERRIDE should be set")
	}
	if !kconfigSet(cfg, "CONFIG_FUNCTION_ERROR_INJECTION") {
		t.Error("CONFIG_FUNCTION_ERROR_INJECTION should be set")
	}
	if kconfigSet(cfg, "CONFIG_BPF_LSM") {
		t.Error("CONFIG_BPF_LSM should not be set (explicitly 'is not set')")
	}
	if kconfigSet(cfg, "CONFIG_NEVER_MENTIONED") {
		t.Error("an absent key should not be set")
	}
	if !kconfigSet(cfg, "CONFIG_SOMETHING") {
		t.Error("CONFIG_SOMETHING=m should count as set (module)")
	}
	if cfg["CONFIG_DEFAULT_HOSTNAME"] != `"(none)"` {
		t.Errorf("CONFIG_DEFAULT_HOSTNAME = %q", cfg["CONFIG_DEFAULT_HOSTNAME"])
	}
}

func TestParseActiveLSMs(t *testing.T) {
	lsms := parseActiveLSMs("lockdown,capability,yama,bpf\n")
	if !containsLSM(lsms, "bpf") {
		t.Errorf("parseActiveLSMs = %v, want containing bpf", lsms)
	}
	if containsLSM(lsms, "selinux") {
		t.Errorf("parseActiveLSMs = %v, should not contain selinux", lsms)
	}
	if got := parseActiveLSMs(""); got != nil {
		t.Errorf("parseActiveLSMs(\"\") = %v, want nil", got)
	}
}

func TestParseLockdownMode(t *testing.T) {
	cases := map[string]string{
		"[none] integrity confidentiality": "none",
		"none [integrity] confidentiality": "integrity",
		"none integrity [confidentiality]": "confidentiality",
		"garbage with no brackets":         "unknown",
		"":                                 "unknown",
	}
	for in, want := range cases {
		if got := parseLockdownMode(in); got != want {
			t.Errorf("parseLockdownMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseErrorInjectionList(t *testing.T) {
	data := "0xffffffff81234560  security_file_open  [function_error_injection]\n" +
		"0xffffffff81234570  commit_creds  [function_error_injection]\n"
	list := parseErrorInjectionList(strings.NewReader(data))
	if !containsFunction(list, "security_file_open") {
		t.Errorf("parseErrorInjectionList = %v, want containing security_file_open", list)
	}
	if !containsFunction(list, "commit_creds") {
		t.Errorf("parseErrorInjectionList = %v, want containing commit_creds", list)
	}
	if containsFunction(list, "sys_execve") {
		t.Errorf("parseErrorInjectionList = %v, should not contain sys_execve", list)
	}
}
