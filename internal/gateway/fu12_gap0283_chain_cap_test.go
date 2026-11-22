package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// TT1 code-close test for rel-1-0-10:GAP-0283 (fix fe7d91bc08, the cap
// MaxChainOperators 4096 -> 512): a hook call at the chain budget is cheap.
// The costliest family is a pipeline of command substitutions: 977 MiB and
// 4.2 s at the old cap of 4096, 59 MiB and 270 ms at 512.
func TestFU12GAP0283HookCallAtTheChainCapIsCheap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes")
	}
	home := filepath.Join(t.TempDir(), "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	api := readingBoundTierTestAPI(t, "claudecode", config.HookPolicyTierDefault)
	command := "echo cap; " + strings.Repeat("$(a)|", shellparse.MaxChainOperators-1) + "a"
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	action := gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, command, true, false)
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("cap=%d bytes=%d action=%s: %d MiB in %s", shellparse.MaxChainOperators, len(command), action, alloc>>20, took)
	if alloc > 160<<20 || took > 2*time.Second {
		t.Errorf("a hook call at the chain cap (%d operators) costs %d MiB in %s, want under 160 MiB and 2 s", shellparse.MaxChainOperators, alloc>>20, took)
	}
}
