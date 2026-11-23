package main

import "fmt"

// usrmergeLinks is step 3 prompt Part C2's exact list: each entry is the
// absolute path that must be a symlink, and the exact target it must
// resolve to (as returned by readlink, i.e. possibly relative).
var usrmergeLinks = []struct {
	path   string
	target string
}{
	{"/bin", "usr/bin"},
	{"/sbin", "usr/sbin"},
	{"/lib", "usr/lib"},
	{"/lib64", "usr/lib64"},
	{"/var/run", "../run"},
}

// checkUsrmerge implements Part C2 given a readlink function (injected so
// this is unit-testable without a real usrmerged filesystem). It returns
// ok=true only if every link in usrmergeLinks is a symlink to exactly its
// expected target; otherwise ok=false and detail names the first mismatch
// found (checked in usrmergeLinks's fixed order, so detail is
// deterministic).
func checkUsrmerge(readlink func(string) (string, error)) (ok bool, detail string) {
	for _, link := range usrmergeLinks {
		target, err := readlink(link.path)
		if err != nil {
			return false, fmt.Sprintf("%s: not a symlink (%v)", link.path, err)
		}
		if target != link.target {
			return false, fmt.Sprintf("%s: symlink target is %q, want %q", link.path, target, link.target)
		}
	}
	return true, ""
}
