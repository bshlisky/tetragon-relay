package main

import (
	"bufio"
	"io"
	"strings"
)

// parseKconfig parses a kernel .config stream (plain text; callers
// transparently gunzip /proc/config.gz before handing it this reader) into
// a map of CONFIG_* name to its value ("y", "m", a quoted string, or "" for
// "is not set"). Step 3 prompt Part C1.
func parseKconfig(r io.Reader) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "CONFIG_") && !strings.HasPrefix(line, "# CONFIG_") {
			continue
		}
		if strings.HasPrefix(line, "# CONFIG_") && strings.HasSuffix(line, "is not set") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "# "), " is not set")
			out[name] = ""
			continue
		}
		name, val, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(name, "CONFIG_") {
			continue
		}
		out[name] = val
	}
	return out
}

// kconfigSet reports whether cfg[name] is "y" or "m" (built-in or module):
// the two values that mean a kernel feature gated by that CONFIG_* symbol
// is actually available at runtime.
func kconfigSet(cfg map[string]string, name string) bool {
	v := cfg[name]
	return v == "y" || v == "m"
}

// parseActiveLSMs parses /sys/kernel/security/lsm's content, a
// comma-separated list of active LSMs in load order (e.g.
// "lockdown,capability,yama,bpf").
func parseActiveLSMs(content string) []string {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	parts := strings.Split(content, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func containsLSM(lsms []string, name string) bool {
	for _, l := range lsms {
		if l == name {
			return true
		}
	}
	return false
}

// parseLockdownMode parses /sys/kernel/security/lockdown's content, which
// lists every mode with the active one in square brackets, e.g.
// "[none] integrity confidentiality".
func parseLockdownMode(content string) string {
	for _, field := range strings.Fields(content) {
		if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
			return strings.TrimSuffix(strings.TrimPrefix(field, "["), "]")
		}
	}
	return "unknown"
}

// parseErrorInjectionList parses /sys/kernel/debug/error_injection/list,
// one "<address> <function_name> <type>" entry per line, returning just
// the function names (step 3 prompt Part C1).
func parseErrorInjectionList(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 {
			out = append(out, fields[1])
		}
	}
	return out
}

// containsFunction reports whether fn appears in the error-injection list.
func containsFunction(list []string, fn string) bool {
	for _, f := range list {
		if f == fn {
			return true
		}
	}
	return false
}
