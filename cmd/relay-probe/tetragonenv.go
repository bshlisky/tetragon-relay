package main

import (
	"sort"
	"strconv"
	"strings"

	"github.com/bshlisky/tetragon-relay/internal/hostprobe"
)

// Step-07b-decisions-3.md F4: report whether the running Tetragon collects
// process environment variables. V1 (run 46117755144) read the v1.8.0 flag
// from `tetragon --help`: --enable-process-environment-variables, a
// boolean. Tetragon takes its options from flags, then TETRAGON_*
// environment variables, then configuration files (a tetragon.yaml and
// tetragon.conf.d directories, one file per option). This reads all three
// from the running process and the files it can read.

const (
	envFlagName = "enable-process-environment-variables"
	envVarName  = "TETRAGON_ENABLE_PROCESS_ENVIRONMENT_VARIABLES"
)

// tetragonConfigDirs are Tetragon's default drop-in directories; a
// --config-dir on its command line is read too.
var tetragonConfigDirs = []string{
	"/usr/lib/tetragon/tetragon.conf.d",
	"/usr/local/lib/tetragon/tetragon.conf.d",
	"/etc/tetragon/tetragon.conf.d",
}

const tetragonYAML = "/etc/tetragon/tetragon.yaml"

// tetragonSources is what relay-probe could read about the running
// Tetragon.
type tetragonSources struct {
	Args    []string          // its command line, argv[1:]
	Environ []string          // its environment
	Files   map[string]string // path -> content: conf.d option files and tetragon.yaml
}

// configDirFromArgs returns --config-dir's value, if given.
func configDirFromArgs(args []string) string {
	for i, a := range args {
		if v, ok := strings.CutPrefix(a, "--config-dir="); ok {
			return v
		}
		if a == "--config-dir" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// decideEnvCollection applies the precedence: flag, then environment, then
// files. pflag boolean flags take "--name" or "--name=<bool>", never a
// separate argument. Among files the result is conservative: any file
// that enables it makes it "on" (the precise order among files is not
// needed for a privacy report that errs towards "on").
func decideEnvCollection(src tetragonSources) (value, source string) {
	flagVal, flagSet := "", false
	for _, a := range src.Args {
		switch {
		case a == "--"+envFlagName:
			flagVal, flagSet = "true", true
		case strings.HasPrefix(a, "--"+envFlagName+"="):
			flagVal, flagSet = strings.TrimPrefix(a, "--"+envFlagName+"="), true
		}
	}
	if flagSet {
		return boolValue(flagVal, "flag")
	}
	for _, kv := range src.Environ {
		if v, ok := strings.CutPrefix(kv, envVarName+"="); ok {
			return boolValue(v, "env")
		}
	}
	paths := make([]string, 0, len(src.Files))
	for p := range src.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var off []string
	for _, p := range paths {
		v, ok := fileValue(p, src.Files[p])
		if !ok {
			continue
		}
		b, err := strconv.ParseBool(v)
		if err != nil || b {
			return hostprobe.EnvCollectionOn, "file:" + p
		}
		off = append(off, p)
	}
	if len(off) > 0 {
		return hostprobe.EnvCollectionOff, "file:" + strings.Join(off, ",")
	}
	return hostprobe.EnvCollectionOff, "default"
}

// fileValue extracts the option's value from a conf.d file (named after
// the option, holding its value) or from tetragon.yaml ("name: value").
func fileValue(path, content string) (string, bool) {
	if strings.HasSuffix(path, "/"+envFlagName) {
		return strings.TrimSpace(content), true
	}
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, envFlagName+":"); ok {
				v = strings.TrimSpace(v)
				if i := strings.Index(v, " #"); i >= 0 {
					v = strings.TrimSpace(v[:i])
				}
				return strings.Trim(v, `"'`), true
			}
		}
	}
	return "", false
}

// boolValue maps a value Tetragon would parse; one it can't parse is
// reported as on, with the raw value, rather than guessed off.
func boolValue(v, source string) (string, string) {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	switch {
	case err != nil:
		return hostprobe.EnvCollectionOn, source + " (unparsable value " + strconv.Quote(v) + ")"
	case b:
		return hostprobe.EnvCollectionOn, source
	default:
		return hostprobe.EnvCollectionOff, source
	}
}
