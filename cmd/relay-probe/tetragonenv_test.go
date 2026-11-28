package main

import (
	"testing"

	"github.com/bshlisky/tetragon-relay/internal/hostprobe"
)

func TestDecideEnvCollection(t *testing.T) {
	conf := "/etc/tetragon/tetragon.conf.d/" + envFlagName
	for _, tc := range []struct {
		name       string
		src        tetragonSources
		want, from string
	}{
		{"default", tetragonSources{}, hostprobe.EnvCollectionOff, "default"},
		{"bare flag (e3's Tetragon)", tetragonSources{Args: []string{"--server-address", "unix:///x", "--enable-process-environment-variables"}}, hostprobe.EnvCollectionOn, "flag"},
		{"flag=false", tetragonSources{Args: []string{"--enable-process-environment-variables=false"}}, hostprobe.EnvCollectionOff, "flag"},
		{"flag beats env", tetragonSources{Args: []string{"--enable-process-environment-variables=0"}, Environ: []string{envVarName + "=true"}}, hostprobe.EnvCollectionOff, "flag"},
		{"unparsable flag value is on", tetragonSources{Args: []string{"--enable-process-environment-variables=yes"}}, hostprobe.EnvCollectionOn, `flag (unparsable value "yes")`},
		{"env", tetragonSources{Environ: []string{"PATH=/bin", envVarName + "=1"}}, hostprobe.EnvCollectionOn, "env"},
		{"env beats file", tetragonSources{Environ: []string{envVarName + "=false"}, Files: map[string]string{conf: "true\n"}}, hostprobe.EnvCollectionOff, "env"},
		{"conf.d true", tetragonSources{Files: map[string]string{conf: "true\n"}}, hostprobe.EnvCollectionOn, "file:" + conf},
		{"conf.d false", tetragonSources{Files: map[string]string{conf: "false"}}, hostprobe.EnvCollectionOff, "file:" + conf},
		{"any file on wins", tetragonSources{Files: map[string]string{conf: "false", tetragonYAML: "x: 1\nenable-process-environment-variables: \"true\" # on\n"}}, hostprobe.EnvCollectionOn, "file:" + tetragonYAML},
		{"yaml without the key", tetragonSources{Files: map[string]string{tetragonYAML: "server-address: x\n"}}, hostprobe.EnvCollectionOff, "default"},
		{"other filter flag is not it", tetragonSources{Args: []string{"--filter-environment-variables=HOME"}}, hostprobe.EnvCollectionOff, "default"},
	} {
		got, from := decideEnvCollection(tc.src)
		if got != tc.want || from != tc.from {
			t.Errorf("%s: got %s (%s), want %s (%s)", tc.name, got, from, tc.want, tc.from)
		}
	}
}

func TestConfigDirFromArgs(t *testing.T) {
	if d := configDirFromArgs([]string{"--config-dir", "/opt/t"}); d != "/opt/t" {
		t.Fatal(d)
	}
	if d := configDirFromArgs([]string{"--config-dir=/opt/u"}); d != "/opt/u" {
		t.Fatal(d)
	}
	if d := configDirFromArgs([]string{"--config-dir"}); d != "" {
		t.Fatal(d)
	}
}
