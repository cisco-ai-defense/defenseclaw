// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestGAP0299LargeHeredocCostStaysBounded is rel-1-0-10:GAP-0299: the hook
// decision of a large here-document (the hook client's reading and the
// gateway's) allocated about half a MiB per KiB of text, because readers
// did per-byte work on the whole command again and again: a regexp that
// built a slice per path token (twice per call), a lexer that read every
// line of the body as a command to look for apply_patch, the nested-body
// measure that parsed a plain body as a shell program, the over-limit twin
// that copied the text (and re-encoded the arguments) to learn it has no
// bounded form, a substring search per rule literal and per registry path
// component, the Windows reader's rune copies and full tokenization, and
// word lists built only to be walked. Each row is one call of a command no
// earlier call made (the parse cache holds none of it), measured in bytes
// allocated, the primary bar, which does not depend on the load of the
// host, and in time, a loose secondary bar of 15 s (rel took 1 to 2 s on a
// loaded build host, the fix about half). The verdicts stay those of rel:
// a benign body alerts as over the evaluation limit, a protected write in
// or beside it blocks.
func TestGAP0299LargeHeredocCostStaysBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the bars are measured for the POSIX readers")
	}
	if hookAnswerRaceBuild {
		t.Skip("an allocation and time guard: the race runtime changes both")
	}
	home := filepath.Join(t.TempDir(), "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	api := readingBoundTierTestAPI(t, "claudecode", config.HookPolicyTierDefault)
	if action := gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, "echo warm", true, false); action != "allow" {
		t.Fatalf("warm-up call: action %q, want allow", action)
	}
	// Each body starts with a line of its own, so no row is in the parse
	// cache of an earlier one.
	row := 0
	text := func(size int) string {
		row++
		line := "Meeting notes: the team reviewed the plan and agreed on the next steps.\n"
		return fmt.Sprintf("row %d\n", row) + strings.Repeat(line, size/len(line))
	}
	lines := func(n int) string {
		row++
		return fmt.Sprintf("cat > notes.txt <<'EOF'\nrow %d\n", row) + strings.Repeat("d | e\n", n) + "EOF\n"
	}
	const mib = 1 << 20
	rows := []struct {
		name, command, want string
		// maxAlloc is the bar in bytes. rel (22db7a8362) allocated 408 MiB
		// for the 393 KB row and 441 to 563 MiB for the 1 MiB rows; the
		// fix allocates about 145 and 235 to 250 MiB.
		maxAlloc uint64
	}{
		{"heredoc-lines 393 KB", lines(65536), "alert", 256 * mib},
		{"text 1 MiB", "cat > notes.txt <<'EOF'\n" + text(1000000) + "EOF\n", "alert", 320 * mib},
		{"text 1 MiB into authorized_keys", "cat > ~/.ssh/authorized_keys <<'EOF'\n" + text(1000000) + "EOF\n", "block", 320 * mib},
		{"text 1 MiB beside an authorized_keys append", "cat > notes.txt <<'EOF'\n" + text(1000000) +
			"EOF\necho ssh-rsa AAAA >> ~/.ssh/authorized_keys\n", "block", 320 * mib},
	}
	for _, row := range rows {
		command := row.command
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		action := gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, command, true, false)
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		allocated := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: %d bytes, %v, %.1f MiB allocated, action %s", row.name, len(command), elapsed.Round(time.Millisecond),
			float64(allocated)/mib, action)
		if action != row.want {
			t.Errorf("%s: action %q, want %q (the rel verdict)", row.name, action, row.want)
		}
		if allocated > row.maxAlloc {
			t.Errorf("%s: the hook decision allocated %.1f MiB, over the %d MiB bar", row.name,
				float64(allocated)/mib, row.maxAlloc/mib)
		}
		if elapsed > 15*time.Second {
			t.Errorf("%s: the hook decision took %v, over the 15 s bar", row.name, elapsed)
		}
	}
}
