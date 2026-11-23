//go:build !linux

package hostprobe

import (
	"fmt"
	"runtime"
)

func currentBootID() (string, error) {
	return "", fmt.Errorf("hostprobe: boot_id is only available on linux (GOOS=%s)", runtime.GOOS)
}
