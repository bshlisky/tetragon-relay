//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"

	"github.com/bshlisky/tetragon-relay/internal/hostprobe"
)

// readTetragonEnvCollection finds the running Tetragon (a process whose
// /proc/<pid>/exe is tetragonBinaryPath; relay-probe runs as root, After=
// tetragon.service) and decides F4's host fact from its command line,
// environment and configuration files.
func readTetragonEnvCollection(tetragonBinaryPath string) (value, source string) {
	want, err := filepath.EvalSymlinks(tetragonBinaryPath)
	if err != nil {
		want = tetragonBinaryPath
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return hostprobe.EnvCollectionUnknown, "cannot read /proc: " + err.Error()
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := "/proc/" + e.Name()
		exe, err := os.Readlink(dir + "/exe")
		if err != nil || exe != want {
			continue
		}
		cmdline, err := os.ReadFile(dir + "/cmdline") //nolint:gosec // G304: /proc/<pid>
		if err != nil {
			return hostprobe.EnvCollectionUnknown, "cannot read Tetragon's command line: " + err.Error()
		}
		environ, _ := os.ReadFile(dir + "/environ") //nolint:gosec // G304: /proc/<pid>
		src := tetragonSources{Args: splitNUL(cmdline), Environ: splitNUL(environ), Files: map[string]string{}}
		if len(src.Args) > 0 {
			src.Args = src.Args[1:]
		}
		dirs := append([]string(nil), tetragonConfigDirs...)
		if d := configDirFromArgs(src.Args); d != "" {
			dirs = append(dirs, d)
		}
		for _, d := range dirs {
			p := filepath.Join(d, envFlagName)
			if b, err := os.ReadFile(p); err == nil { //nolint:gosec // G304: Tetragon's own config paths
				src.Files[p] = string(b)
			}
		}
		if b, err := os.ReadFile(tetragonYAML); err == nil {
			src.Files[tetragonYAML] = string(b)
		}
		return decideEnvCollection(src)
	}
	return hostprobe.EnvCollectionUnknown, "no running process with exe " + want
}

func splitNUL(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = string(p)
	}
	return out
}
