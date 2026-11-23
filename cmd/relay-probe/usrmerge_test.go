package main

import (
	"errors"
	"testing"
)

func TestCheckUsrmerge_AllCorrect(t *testing.T) {
	ok, detail := checkUsrmerge(func(path string) (string, error) {
		for _, l := range usrmergeLinks {
			if l.path == path {
				return l.target, nil
			}
		}
		return "", errors.New("unexpected path")
	})
	if !ok || detail != "" {
		t.Fatalf("ok=%v detail=%q, want ok=true detail=\"\"", ok, detail)
	}
}

func TestCheckUsrmerge_NotASymlink(t *testing.T) {
	ok, detail := checkUsrmerge(func(_ string) (string, error) {
		return "", errors.New("readlink: not a symlink")
	})
	if ok {
		t.Fatal("ok=true for a non-symlink")
	}
	if detail == "" {
		t.Fatal("empty detail for a failing check")
	}
}

func TestCheckUsrmerge_WrongTarget(t *testing.T) {
	ok, detail := checkUsrmerge(func(path string) (string, error) {
		if path == "/bin" {
			return "/usr/bin", nil // absolute, not the expected relative "usr/bin"
		}
		for _, l := range usrmergeLinks {
			if l.path == path {
				return l.target, nil
			}
		}
		return "", errors.New("unexpected path")
	})
	if ok {
		t.Fatal("ok=true for a mismatched symlink target")
	}
	if detail == "" {
		t.Fatal("empty detail for a failing check")
	}
}
