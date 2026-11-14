// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-0534: on the 1.0.7 rc2 build one PowerShell-tool call with a
// comment-glued value frame overflowed the gateway goroutine stack in the
// recovered-parse reader, and every connector of the account lost
// enforcement until restart. The call is now answered within the hook
// window under a capped stack, through the hook client write evidence and
// the gateway decision, for both connectors, per user and managed. The
// protected form keeps a finding (action blocks, observe alerts), and the
// ordinary calls around it are answered as before. The ordinary twin behind
// the same unparsed statement, sent without client write evidence, takes
// the profile-decided evaluation-limit finding on a per-user gateway (which
// reads the recovered-parse bound itself, as the hook client does), and
// allows on a managed gateway, which keeps the client evidence.
func TestGAP0534HookCallIsAnsweredWithoutCrash(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	const (
		form     = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/.defenseclaw`
		fixed    = "0`@A>`; Remove-Item -Recurse -Force ~/.defenseclaw"
		ordinary = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/project/output`
		benign   = "Get-ChildItem -Name"
	)
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		tool := "PowerShell"
		if connector == "codex" {
			tool = "exec_command"
		}
		for _, managed := range []bool{false, true} {
			cell := connector + map[bool]string{false: "/per-user", true: "/managed"}[managed]
			judge := func(command string, clientEvidence bool) ([]RuleFinding, string) {
				t.Helper()
				ctx := context.Background()
				if managed {
					ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
				}
				start := time.Now()
				var resolved map[string]string
				if clientEvidence {
					payload, err := json.Marshal(map[string]any{
						"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd,
						"tool_input": map[string]string{"command": command},
					})
					if err != nil {
						t.Fatal(err)
					}
					resolved, _ = hookpaths.Decode(hookpaths.Resolve(payload))
				}
				findings := dispatchTrustedAction(ctx, trustedActionRequest{
					Input:     actionfacts.Input{Tool: tool, Command: command, CWD: cwd, ActiveHome: home},
					Connector: connector, EnforcementCapable: true, ResolvedWriteTargets: resolved,
				})
				if took := time.Since(start); took > time.Second {
					t.Errorf("%s: %q answered in %s", cell, command, took)
				}
				return findings, buildVerdict(findings, "tool_call").Action
			}
			if _, action := judge(benign, true); action != guardrailActionAllow {
				t.Errorf("%s: benign call before the form: %s", cell, action)
			}
			protected := []string{form}
			if runtime.GOOS != "windows" { // Windows hookexec sends no client write evidence.
				protected = append(protected, fixed)
			}
			for _, command := range protected {
				if findings, _ := judge(command, true); len(findings) == 0 {
					t.Errorf("%s: protected recovered form %q has no finding", cell, command)
				}
			}
			findings, action := judge(ordinary, false)
			bound := !managed && (hookpaths.ShellParseReason(connector, tool, ordinary, cwd, home) == "shell-parse-bound")
			if !managed && runtime.GOOS != "windows" && !bound {
				t.Errorf("%s: ordinary twin is not read as shell-parse-bound", cell)
			}
			switch {
			case bound && (len(findings) != 1 || findings[0].RuleID != "ACTION-COMPOUND-LIMIT"):
				t.Errorf("%s: ordinary twin without write evidence: %s %v, want the evaluation-limit finding", cell, action, findings)
			case !bound && action != guardrailActionAllow:
				t.Errorf("%s: ordinary twin without write evidence: %s", cell, action)
			}
			if _, action := judge(benign, true); action != guardrailActionAllow {
				t.Errorf("%s: benign call after the form: %s", cell, action)
			}
		}
	}
}
