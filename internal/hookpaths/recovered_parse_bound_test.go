// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// gap0534Forms are the GAP-0534 call and the variants of its class. On the
// 1.0.7 rc2 build the Bash recovery parse of the first form printed a call
// that parsed back to itself, and the recovered call was read again with a
// fresh depth, until the goroutine stack overflowed (a fatal error that
// exits the gateway). The other forms re-enter the same readers through a
// printed fixed point, nested shell bodies, trap handlers, called functions
// and many recovered calls in one command.
func gap0534Forms(tail string) []struct{ name, command string } {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	const glued = `Write-Output $(.\a[1]<#x#>); `
	wrap := func(n int, body string, frame func(string) string) string {
		for range n {
			body = frame(body)
		}
		return body
	}
	shell := func(body string) string { return "bash -c " + quote(body) }
	trap := func(body string) string { return "trap " + quote(body) + " EXIT; true" }
	functions := "f0(){ " + glued + tail + "; }; "
	for i := 1; i < 24; i++ {
		functions += fmt.Sprintf("f%d(){ f%d; f%d; }; ", i, i-1, i-1)
	}
	return []struct{ name, command string }{
		{"case", glued + tail},
		{"printed fixed point", "0`@A>`; " + tail},
		{"glued double quote", `Write-Output $(a"b"#); ` + tail},
		{"array frame", `Write-Output @(.\a[1]<#x#>); ` + tail},
		{"script block", `& {.\a[1]#}; ` + tail},
		{"repeated frames", strings.Repeat(glued, 200) + tail},
		{"repeated fixed points", strings.Repeat("0`@A>`; ", 400) + tail},
		{"nested shells", wrap(6, glued+tail, shell)},
		{"nested traps", wrap(6, glued+tail, trap)},
		{"function fan-out", functions + "f23"},
	}
}

// GAP-0534: every reader of a hook call finishes each form under a capped
// stack, in bounded time and allocation, on every host. A protected tail
// keeps an unproven-write class: the evidence case on every host (as
// TestGAP0534RecoveredParseFixedPoint), and the printed fixed point and the
// hook client write evidence where the hook client sends that evidence
// (Windows hookexec sends none).
func TestGAP0534RecoveredParseStaysBounded(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tail := range []struct {
		name, command string
		protected     bool
	}{
		{"protected", "Remove-Item -Recurse -Force ~/.defenseclaw", true},
		{"ordinary", "Remove-Item -Recurse -Force ~/project/output", false},
	} {
		for _, form := range gap0534Forms(tail.command) {
			t.Run(form.name+"/"+tail.name, func(t *testing.T) {
				// The 3 s window is a wall-clock window of the host: a native
				// Windows box shared with other runs took 7.4-13.2 s (GAP-0587).
				// It stretches with the host's slowdown (testenv.HostSlowdown),
				// and a run over it is measured again, up to three times, each
				// at three times the window of the one before: the readers
				// that never finish (the stack overflow, the unbounded
				// recovery this test guards) still fail every run, and what a
				// run must produce is asserted below, unchanged.
				var before, after runtime.MemStats
				var reason string
				var resolved map[string]map[string]string
				var elapsed time.Duration
				slow := testenv.HostSlowdown()
				for try := 1; ; try++ {
					runtime.GC()
					runtime.ReadMemStats(&before)
					start := time.Now()
					reason = UnprovenProtectedWrite(form.command, cwd, home)
					for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell} {
						ActionCommandDecisionWithDialectAndGlobFacts(form.command, cwd, home, dialect, nil)
						ActionCommandAuditReasonWithDialect(form.command, cwd, home, dialect)
					}
					ActionStateTargetMention(form.command, cwd, home)
					resolved = map[string]map[string]string{}
					for _, tool := range []string{"PowerShell", "Bash", "exec_command"} {
						payload, err := json.Marshal(map[string]any{
							"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd,
							"tool_input": map[string]string{"command": form.command},
						})
						if err != nil {
							t.Fatal(err)
						}
						resolved[tool], _ = Decode(Resolve(payload))
					}
					elapsed = time.Since(start)
					runtime.ReadMemStats(&after)
					window := testenv.Scale(3*time.Second, slow)
					if elapsed <= window {
						break
					}
					if try == 3 {
						t.Errorf("readers took %s, over the %s window at host slowdown x%.1f, in 3 runs", elapsed, window, slow)
						break
					}
					t.Logf("run %d: readers took %s, over the %s window at host slowdown x%.1f", try, elapsed, window, slow)
					slow = 3 * max(slow, testenv.HostSlowdown())
				}
				// The product build stays under 128 MiB; the -race build
				// allocates a few percent more (sync.Pool is not kept there).
				limit := uint64(128 << 20)
				if raceDetector {
					limit = limit * 5 / 4
				}
				if used := after.TotalAlloc - before.TotalAlloc; used > limit {
					t.Errorf("readers allocated %d MiB", used>>20)
				}
				if !tail.protected || form.name != "case" && (form.name != "printed fixed point" || !hookWriteEvidenceHost()) {
					return
				}
				if reason == "" {
					t.Error("protected recovered form has no unproven-write class")
				}
				if hookWriteEvidenceHost() && resolved["PowerShell"][UnprovenReasonKey] == "" {
					t.Error("hook client write evidence lost the unproven-write class")
				}
			})
		}
	}
}
