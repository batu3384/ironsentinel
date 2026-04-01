//go:build windows

package core

import "fmt"

func availableDiskBytes(path string) (uint64, error) {
	return 0, fmt.Errorf("disk availability probe unsupported on windows for this build")
}
