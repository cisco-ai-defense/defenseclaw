//go:build windows

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWriteWithLock on Windows falls back to a direct write without file
// locking. Sandbox mode is Linux-only; this stub exists so the rest of the
// binary compiles on Windows.
func AtomicWriteWithLock(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("sandbox: create directory %s: %w", dir, err)
	}
	return os.WriteFile(path, data, perm)
}
