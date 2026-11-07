// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-6:GAP-0675 round 10: a verdict whose only basis is the evaluation
// limit (the reader could not analyse the call, no target is proven) is an
// alert outside the strict profile and a block in strict. A proven finding
// beside the limit (a self-protection write, a protected target the hook
// client proved) decides on its own, in every profile; the Secure Client
// integration is unchanged.
func TestEvaluationLimitOnlyVerdictMapsByProfile(t *testing.T) {
	blockAt := func(severity string) string {
		switch severity {
		case "CRITICAL", "HIGH":
			return guardrailActionBlock
		case "MEDIUM":
			return guardrailActionAlert
		}
		return guardrailActionAllow
	}
	limit := trustedActionLimitFindings(true)
	observed := trustedActionLimitFindings(false)
	namesState := slices.Clone(limit)
	namesState[0].namesState = true
	state := RuleFinding{RuleID: "tamper.detector_state_write", Severity: "HIGH"}
	keys := RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL"}
	advisory := RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL", enforcement: findingEnforcementAlertOnly}
	with := func(findings []RuleFinding, more ...RuleFinding) []RuleFinding {
		return append(slices.Clone(findings), more...)
	}
	for _, tc := range []struct {
		name         string
		findings     []RuleFinding
		secureClient bool
		strict       bool
		want         string
	}{
		{"limit only, default", limit, false, false, "alert"},
		{"limit only, strict", limit, false, true, "block"},
		{"limit only, Secure Client keeps the block", limit, true, false, "block"},
		{"limit that cannot block changes nothing", observed, false, false, "allow"},
		{"limit on a call that names the state folder blocks in default", namesState, false, false, "block"},
		{"limit on a call that names the state folder, Secure Client", namesState, true, false, "block"},
		{"limit and a proven keys finding block in default", with(limit, keys), false, false, "block"},
		{"limit and self-protection block in default", with(limit, state), false, false, "block"},
		{"limit and an advisory finding alert in default", with(limit, advisory), false, false, "alert"},
		{"limit and an advisory finding block in strict", with(limit, advisory), false, true, "block"},
		{"no limit, no cap", with(nil, keys), false, false, "block"},
	} {
		before := slices.Clone(tc.findings)
		strictCalls := 0
		got := guardrailActionForProfile(tc.findings, tc.secureClient, func() bool { strictCalls++; return tc.strict }, blockAt)
		if got != tc.want {
			t.Errorf("%s: action=%q want %q", tc.name, got, tc.want)
		}
		if len(before) != len(tc.findings) {
			t.Fatalf("%s: the mapping changed the caller findings", tc.name)
		}
		if tc.name == "no limit, no cap" && strictCalls != 0 {
			t.Errorf("%s: the posture was read for a call without a limit finding", tc.name)
		}
	}
}

// limitHookCell sends one command through the Claude Code or Codex hook as a
// per-user gateway or as a managed peer (ProtectHome) with the hook client's
// header, and returns the answer's action and finding ids.
func limitHookCell(t *testing.T, api *APIServer, connector, tool, home, cwd, command string, managed bool) (string, []string) {
	t.Helper()
	ctx := context.Background()
	body := mustJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "limit-profile", "cwd": cwd,
		"tool_name": tool, "tool_input": map[string]any{"command": command}})
	if targets, ok := hookpaths.Decode(hookpaths.Resolve(body)); ok {
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, targets)
	}
	if managed {
		ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
		homes := filepath.Dir(home)
		if err := os.Chmod(homes, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(homes, 0o700) }()
	}
	if connector == "claudecode" {
		resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", CWD: cwd, ToolName: tool, ToolInput: map[string]any{"command": command},
		})
		return resp.Action, resp.Findings
	}
	resp := api.evaluateCodexHook(ctx, codexHookRequest{
		HookEventName: "PreToolUse", CWD: cwd, ToolName: "exec_command", ToolInput: map[string]any{"cmd": command},
	})
	return resp.Action, resp.Findings
}

// A call the reader cannot analyse (an earlier PowerShell statement it cannot
// parse, or more statements than the budget) and that proves no protected
// target runs with a visible alert in the default and permissive profiles,
// per-user and managed, on both hook routes, and blocks in strict. A write
// to DefenseClaw state, or to a file the call names, keeps its block in every
// profile. Documented limit: an unparseable leading statement can hide a
// write in default; strict blocks it and the LLM judge is the second layer.
func TestEvaluationLimitOnlyCallAlertsOutsideStrict(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(cwd, "normal"), filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	gap0568StateFile(t, home)
	for _, file := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "notes.txt"),
		filepath.Join(cwd, "settings.json"), filepath.Join(cwd, "hooks.json")} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })

	const limit = "ACTION-COMPOUND-LIMIT"
	unparsed := `Write-Output $(.\a[1]<#x#>); `
	over := gap0568Assignments(200)
	alertOutsideStrict := map[string]string{"default": "alert", "permissive": "alert", "strict": "block"}
	everywhere := map[string]string{"default": "block", "permissive": "block", "strict": "block"}
	allowed := map[string]string{"default": "allow", "permissive": "allow", "strict": "allow"}
	rows := []struct {
		name, tool, command string
		want                map[string]string
		// limitOnly rows carry the limit finding in every profile.
		limitOnly bool
	}{
		{"ordinary settings removal behind an unparsed statement", "PowerShell", unparsed + "Remove-Item -Recurse -Force ~/project/settings.json", alertOutsideStrict, true},
		{"ordinary hooks removal behind an unparsed statement", "PowerShell", unparsed + "Remove-Item -Recurse -Force ~/project/hooks.json", alertOutsideStrict, true},
		{"ordinary parent step removal behind an unparsed statement", "PowerShell", unparsed + "Remove-Item -Recurse -Force ~/project/normal/../settings.json", alertOutsideStrict, true},
		{"state folder removal behind an unparsed statement", "PowerShell", unparsed + "Remove-Item -Recurse -Force ~/.defenseclaw", everywhere, false},
		{"state folder removal, quoted name, behind an unparsed statement", "PowerShell", unparsed + "Remove-Item -Recurse -Force ~/.defense'claw", everywhere, false},
		{"ordinary command over the statement budget", "Bash", over, alertOutsideStrict, true},
		{"DefenseClaw state write over the statement budget", "Bash", over + "; printf changed >> ~/.defenseclaw/config.yaml", everywhere, false},
		// The documented limit: no target is proven in these calls, so they
		// alert outside strict. Strict blocks them and the LLM judge is the
		// second layer where it is configured.
		{"keys append behind an unparsed statement", "PowerShell", unparsed + "Add-Content ~/.ssh/authorized_keys x", alertOutsideStrict, true},
		{"link into the keys file behind an unparsed statement", "PowerShell", unparsed + "Add-Content ~/project/keylink x", alertOutsideStrict, true},
		{"keys append over the statement budget", "Bash", over + "; echo k >> ~/.ssh/authorized_keys", alertOutsideStrict, true},
		{"keys append the call names", "Bash", "printf marker >> ~/.ssh/authorized_keys", everywhere, false},
		{"ordinary write", "Bash", "printf marker >> notes.txt", allowed, false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, posture := range []string{"default", "permissive", "strict"} {
			api := instructionProtectionTestAPIWithPack(t, connector, "action", "", posture)
			for _, managed := range []bool{false, true} {
				for _, row := range rows {
					got, findings := limitHookCell(t, api, connector, row.tool, home, cwd, row.command, managed)
					if want := row.want[posture]; got != want {
						t.Errorf("%s %s managed=%t %s: action=%q want %q findings=%v", connector, posture, managed, row.name, got, want, findings)
					}
					hasLimit := slices.ContainsFunc(findings, func(f string) bool { return len(f) >= len(limit) && f[:len(limit)] == limit })
					if row.limitOnly && !hasLimit {
						t.Errorf("%s %s managed=%t %s: findings=%v, want %s named", connector, posture, managed, row.name, findings, limit)
					}
				}
			}
		}
	}
}

// The text test of a call no reader could analyse: the state folder spelled
// plainly, quoted, escaped or in any case is named; other words are not.
func TestTextNamesStateFolder(t *testing.T) {
	for command, want := range map[string]bool{
		"Remove-Item ~/.defenseclaw":               true,
		"rm -rf ~/.Defense'claw/":                  true,
		`rm -rf ~/.defense\claw`:                   true,
		"rm -rf ~/.defense`claw":                   true,
		"openclaw status && git commit -m defense": false,
		"printf x >> notes.txt":                    false,
		"":                                         false,
	} {
		if got := textNamesStateFolder(command); got != want {
			t.Errorf("%q: names the state folder = %t, want %t", command, got, want)
		}
	}
}
