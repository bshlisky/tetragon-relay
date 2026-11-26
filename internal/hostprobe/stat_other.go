//go:build !linux

package hostprobe

import "os"

// platformStatOpenFile: freshness cannot be established off linux, so
// Load always fails closed there.
func platformStatOpenFile(*os.File) (fileInfo, error) {
	return fileInfo{}, ErrHostFactsUnsupported
}
