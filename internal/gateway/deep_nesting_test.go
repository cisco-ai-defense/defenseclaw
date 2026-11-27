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
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A very long command of nested ( made a hook-path reader recurse until
// the goroutine stack overflowed, a fatal error that exits the gateway for
// every user (GAP-2537, native Windows). Every reader is bounded: past
// shellparse.MaxNestingDepth the call takes the over-limit path at once,
// for the command input and for a command argument, on any tool. The stack
// bound makes the old recursion fail on every OS. "At once" is the work of
// the call, the CPU time of this process (processWork), not its wall-clock
// time: the verdict held in every red run, and only the wall-clock bound
// moved with the box (a unit judged in 4-5 s at load 80-120 on 64 cores
// under -race, rel-1-0-10:GAP-2129). A race build scales the bound by
// raceScanBudgetScale, the race detector's own extra work.
func TestDeeplyNestedCommandTakesTheOverLimitPath(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	installDefaultProfileConnector(t, "claudecode")
	home := t.TempDir()
	tails := []string{"\ncat ~/.defenseclaw/config.yaml", "\necho done"}
	var most time.Duration
	for _, unit := range []string{"(", "$(", "$((", "{ ", "\"$(", "[IO.File]::WriteAllText("} {
		for _, tail := range tails {
			command := strings.Repeat(unit, (180<<10)/len(unit)) + tail
			args, _ := json.Marshal(map[string]string{"command": command})
			for _, input := range []actionfacts.Input{
				{Tool: "Bash", Command: command, CWD: home, ActiveHome: home},
				{Tool: "Bash", Args: args, CWD: home, ActiveHome: home},
				{Tool: "PowerShell", Args: args, CWD: home, ActiveHome: home, DialectHint: actionfacts.DialectPowerShell},
			} {
				start := processWork(t)
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: "claudecode", EnforcementCapable: true,
				})
				work := processWork(t) - start
				most = max(most, work)
				if work > 3*time.Second*raceScanBudgetScale {
					t.Errorf("%s unit %q: judged with %s of work, want under %s", input.Tool, unit, work, 3*time.Second*raceScanBudgetScale)
				}
				if verdict := buildVerdict(findings, "tool_call"); verdict.Action != "block" {
					t.Errorf("%s unit %q tail %q: action %q, want block", input.Tool, unit, tail, verdict.Action)
				}
			}
		}
	}
	t.Logf("most work of one over-limit call: %s", most.Round(time.Millisecond))
	// Nesting past the analysis depth bound, short of the reader bound, is
	// TRUNCATED at cap=depth (s7/cap-floor, rel-1-0-10:GAP-0688, as
	// TestCapFloorDepthTruncatesEveryCall): the unknown tier of the pack, an
	// alert in the default profile, never a block outside strict and never the
	// over-limit path of the reader bound above.
	nested40 := "echo " + strings.Repeat("$(echo ", 40) + "x" + strings.Repeat(")", 40)
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:     actionfacts.Input{Tool: "Bash", Command: nested40, CWD: home, ActiveHome: home},
		Connector: "claudecode", EnforcementCapable: true,
	})
	if !boundedHasLimit(FindingStrings(findings), bounded.Depth, true) {
		t.Errorf("40 nested substitutions: no cap=depth limit finding, %v", FindingStrings(findings))
	}
	if got := guardrailActionForProfile(findings, false, func() bool { return false }, boundedTestActionFor); got != guardrailActionAlert {
		t.Errorf("40 nested substitutions: %s in the default profile, want alert (%v)", got, FindingStrings(findings))
	}
	// Ordinary nesting is read as before.
	for _, command := range []string{
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
