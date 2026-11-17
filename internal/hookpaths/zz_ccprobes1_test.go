// Scratch code-close probes (S7 lane s7-probe1, test-only branch s7/ccprobes-1).
// Old-API probes of rel-1-0-10 gaps in the hook client reading; want red at
// the pre-fix sha, green at rel.

package hookpaths

import (
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-10:GAP-0437 (P1 security): a malformed $(( arithmetic never panics
// the hook client reading (UnprovenProtectedWrite, Resolve).
func TestCCP1GAP0437MalformedArithmeticNeverPanicsTheReader(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX reading")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "work")
	for _, command := range []string{"h=$((t d", "h=$((t d))", "echo x >> ~/.ssh/authorized_keys\nh=$((t d"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("UnprovenProtectedWrite(%q): panic %v", command, r)
				}
			}()
			t.Logf("UnprovenProtectedWrite(%q) = %q", command, UnprovenProtectedWrite(command, cwd, home))
		}()
	}
}
