// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func gap0677Nested(levels int, inner string) string {
	for i := 0; i < levels; i++ {
		inner = "bash -c '" + strings.ReplaceAll(inner, "'", `'\''`) + "'"
	}
	return inner
}

// GAP-0677: a call of ten to twelve nested bash -c bodies (0.09 to 0.8
// MB) took 3 to 8.5 s through the hook client and the gateway, past the
// hook answer window. It is past the reading bounds now: the hook client
// sends incomplete evidence and the gateway takes the over-limit path at
// once, for both connectors, with the evaluation-limit finding the profile
// decides, whatever the target (an alert in the default profile, a block
// in strict, TestGAP0677NestedBodiesPastTheBoundAreGradedByTarget). A single bash -c
// script is still read and allowed (the shellparse test weighs one of 400
// KB).
func TestGAP0677NestedShellBodiesAreDecidedWithinTheHookWindow(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	ordinaryBody := "bash -c '" + strings.Repeat("printf %s "+strings.Repeat("word ", 200)+"; ", 10) + "'"
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		tool := "Bash"
		if connector == "codex" {
			tool = "exec_command"
		}
		decide := func(command string) ([]RuleFinding, time.Duration) {
			t.Helper()
			payload, err := json.Marshal(map[string]any{
				"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd,
				"tool_input": map[string]string{"command": command},
			})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			resolved, _ := hookpaths.Decode(hookpaths.Resolve(payload))
			findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
				Input:     actionfacts.Input{Tool: tool, Command: command, CWD: cwd, ActiveHome: home},
				Connector: connector, EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			return findings, time.Since(start)
		}
		// Eleven levels (266 KB) to an ordinary target for one connector,
		// ten to a protected one for the other; the script once (test
		// budget).
		levels, target := 11, "~/project/output"
		if connector == "codex" {
			levels, target = 10, "~/.defenseclaw"
		}
		command := gap0677Nested(levels, "rm -rf "+target)
		findings, took := decide(command)
		if took > 1500*time.Millisecond {
			t.Errorf("%s: %d nested bodies (%d bytes) to %s decided in %s", connector, levels, len(command), target, took)
		}
		if ids := findingIDs(findings); len(ids) != 1 || ids[0] != "ACTION-COMPOUND-LIMIT" ||
			buildVerdict(findings, "tool_call").Action != guardrailActionBlock {
			t.Errorf("%s: %d nested bodies to %s: %s %v, want the over-limit block", connector, levels, target, buildVerdict(findings, "tool_call").Action, ids)
		} else if findings[0].omittedOperand {
			t.Errorf("%s: %d nested bodies to %s: keeps the block in every profile", connector, levels, target)
		}
		if connector == "codex" {
			continue
		}
		findings, _ = decide(ordinaryBody)
		if action := buildVerdict(findings, "tool_call").Action; action != guardrailActionAllow {
			t.Errorf("%s: ordinary bash -c script (%d bytes): %s %v", connector, len(ordinaryBody), action, findingIDs(findings))
		}
	}
}
