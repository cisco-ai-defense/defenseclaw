// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A very long command of nested ( made a hook-path reader recurse until
// the goroutine stack overflowed, a fatal error that exits the gateway for
// every user (GAP-2537, native Windows). Every reader is bounded: past
// shellparse.MaxNestingDepth the call takes the over-limit path at once,
// for the command input and for a command argument, on any tool. The stack
// bound makes the old recursion fail on every OS.
func TestDeeplyNestedCommandTakesTheOverLimitPath(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	installDefaultProfileConnector(t, "claudecode")
	home := t.TempDir()
	tails := []string{"\ncat ~/.defenseclaw/config.yaml", "\necho done"}
	for _, unit := range []string{"(", "$(", "$((", "{ ", "\"$(", "[IO.File]::WriteAllText("} {
		for _, tail := range tails {
			command := strings.Repeat(unit, (180<<10)/len(unit)) + tail
			args, _ := json.Marshal(map[string]string{"command": command})
			for _, input := range []actionfacts.Input{
				{Tool: "Bash", Command: command, CWD: home, ActiveHome: home},
				{Tool: "Bash", Args: args, CWD: home, ActiveHome: home},
				{Tool: "PowerShell", Args: args, CWD: home, ActiveHome: home, DialectHint: actionfacts.DialectPowerShell},
			} {
				start := time.Now()
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: "claudecode", EnforcementCapable: true,
				})
				if took := time.Since(start); took > 3*time.Second {
					t.Errorf("%s unit %q: judged in %s", input.Tool, unit, took)
				}
				if verdict := buildVerdict(findings, "tool_call"); verdict.Action != "block" {
					t.Errorf("%s unit %q tail %q: action %q, want block", input.Tool, unit, tail, verdict.Action)
				}
			}
		}
	}
	// Ordinary nesting is read as before.
	for _, command := range []string{
		"echo " + strings.Repeat("$(echo ", 40) + "x" + strings.Repeat(")", 40),
		"(cd src && (make && (echo ok)))",
		"find . \\( -name a -o -name b \\) -print",
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:     actionfacts.Input{Tool: "Bash", Command: command, CWD: home, ActiveHome: home},
			Connector: "claudecode", EnforcementCapable: true,
		})
		if verdict := buildVerdict(findings, "tool_call"); verdict.Action == "block" {
			t.Errorf("%q: blocked, %v", command, FindingStrings(findings))
		}
	}
}
