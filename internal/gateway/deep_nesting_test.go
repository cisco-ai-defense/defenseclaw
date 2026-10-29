// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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

// The command of a Codex apply_patch call is a patch envelope, not shell:
// a patch adding ordinary text with more than shellparse.MaxNestingDepth
// unclosed (, { or [ (ANSI colour escapes) is judged by its targets, in the
// OSS and managed paths, and a key patch with the same text still blocks.
// A 180 KiB patch of ( is read without a stack overflow (GAP-2561).
func TestDeepPatchBodyIsJudgedByItsTargets(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	installDefaultProfileConnector(t, "codex")
	home := t.TempDir()
	cwd := home + "/project"
	patch := func(path, body string) string {
		return "*** Begin Patch\n*** Add File: " + path + "\n" + body + "*** End Patch\n"
	}
	golden := cwd + "/testdata/log.golden"
	colored := strings.Repeat("+\x1b[31mERROR\x1b[0m build step failed\n", 600)
	for _, row := range []struct {
		name, body, path string
		block            bool
	}{
		{"P01 colored", colored, golden, false},
		{"P02 600 (", strings.Repeat("+(\n", 600), golden, false},
		{"P07 520 [", "+" + strings.Repeat("[", 520) + "\n", golden, false},
		{"K1 colored key patch", colored, home + "/.ssh/authorized_keys", true},
	} {
		for _, call := range []struct {
			key     string
			managed bool
		}{{"command", false}, {"command", true}, {"input", false}, {"input", true}} {
			managed := call.managed
			args, _ := json.Marshal(map[string]string{call.key: patch(row.path, row.body)})
			ctx := context.Background()
			if managed {
				ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
			}
			findings := dispatchTrustedAction(ctx, trustedActionRequest{
				Input:     actionfacts.Input{Tool: "apply_patch", Args: args, CWD: cwd, ActiveHome: home},
				Connector: "codex", EnforcementCapable: true,
			})
			if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
				t.Errorf("%s %s managed=%v: block %v, want %v: %v", row.name, call.key, managed, blocked, row.block, FindingStrings(findings))
			}
		}
	}
	for _, unit := range []string{"(", "[IO.File]::WriteAllText(", "$("} {
		body := "+" + strings.Repeat(unit, (180<<10)/len(unit)) + "\n"
		args, _ := json.Marshal(map[string]string{"command": patch(golden, body)})
		start := time.Now()
		_ = dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:     actionfacts.Input{Tool: "apply_patch", Args: args, CWD: cwd, ActiveHome: home},
			Connector: "codex", EnforcementCapable: true,
		})
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("unit %q: judged in %s", unit, took)
		}
	}
}
