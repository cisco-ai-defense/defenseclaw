//go:build !windows

package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RV5-7 (GAP-0784): a changed other file over the scan cap (8 MiB) is not
// read into memory, so its placeholder was never looked for and the file
// landed with DC_SECRET_1 in it. It is now checked by streaming it; one that
// holds a placeholder stays out, one that does not lands.
func TestRV57OversizeOtherFileWithPlaceholderStaysOut(t *testing.T) {
	e, fs, _ := s9aCopy(t, "rv57big")
	pad := strings.Repeat("x", DefaultScanMaxFileBytes+1024)
	fs.write(remoteRepo+"/big.txt", pad+"\nDC_SECRET_1\n")
	fs.write(remoteRepo+"/bigok.txt", pad+"\nno placeholder\n")
	fs.write(remoteRepo+"/ok.txt", "fine\n")
	rv5Pull(t, e, fs, "rv57big", map[string]string{"ok.txt": "fine\n"})
	if _, err := os.Stat(filepath.Join(e.project, "big.txt")); err == nil {
		t.Error("big.txt landed with a placeholder in it")
	}
}
