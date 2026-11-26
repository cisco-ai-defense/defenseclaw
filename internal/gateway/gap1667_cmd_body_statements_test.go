// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-10 GAP-1667: on a Windows hook host a cmd /c body is the command
// line cmd runs, statements joined by & && || and |. The archive reading
// took the whole body as one call: a body whose first statement is not the
// extractor (cmd /c "copy /y cfgarch.tar ok.tar && tar -xf ok.tar -C
// %USERPROFILE%") was not read at all, and a statement after the extractor
// was read as its members, so the archive was never judged by what it
// holds. Each statement is now read (the cmd statement splitter the effects
// lowering uses), the copy before the tar stages the archive, and the
// extraction is the same state write as its PowerShell spelling (GAP-0747
// tiers: alert in default, permissive and managed, block in strict and
// managed-strict). The benign twins keep their allow. GAP-1708: the switches
// before /c are the one cmd switch set (/x is read).
func TestGAP1667CmdBodyStatementsReadEachExtraction(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	previousShell := codexShellRunsPowerShell
	codexShellRunsPowerShell = true
	t.Cleanup(func() { codexShellRunsPowerShell = previousShell })
	home := t.TempDir()
	cwd := filepath.Join(home, "fcwork")
	for _, folder := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(cwd, "out"), filepath.Join(cwd, "build")} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "a.txt"), []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	gap1633Tar(t, filepath.Join(cwd, "cfgarch.tar"), "config.yaml")
	gap1633Tar(t, filepath.Join(cwd, "ok.tar"), "notes.txt")
	gap1633Tar(t, filepath.Join(cwd, "homestate.tar"), ".defenseclaw/config.yaml")
	// A staged archive landing in the home may also take the GAP-1634
	// authorized-keys block in every tier (the home holds .ssh), as the
	// listed-then-copied rows of the GAP-1633 test do.
	staged := map[string]bool{
		`cmd /c "copy /y homestate.tar ok.tar && tar -xf ok.tar -C %USERPROFILE%"`:           true,
		`cmd /x /c "copy /y homestate.tar ok.tar && tar -xf ok.tar -C %USERPROFILE%"`:        true,
		`cmd /c "copy /y cfgarch.tar ok.tar & tar -xf ok.tar -C %USERPROFILE%\.defenseclaw"`: true,
	}
	writes := []string{
		`cmd /c "copy /y homestate.tar ok.tar && tar -xf ok.tar -C %USERPROFILE%"`,
		`cmd /x /c "copy /y homestate.tar ok.tar && tar -xf ok.tar -C %USERPROFILE%"`,
		`cmd /c "copy /y cfgarch.tar ok.tar & tar -xf ok.tar -C %USERPROFILE%\.defenseclaw"`,
		`cmd /c "tar -xf homestate.tar -C %USERPROFILE% & dir"`,
		`cmd /c "tar -xf homestate.tar -C %USERPROFILE% || echo failed"`,
		`cmd /d /c "dir & tar -xf homestate.tar -C %USERPROFILE%"`,
	}
	allowed := []string{
		`cmd /c "copy a.txt b.txt && tar -xf ok.tar -C build"`,
		`cmd /c "tar -xf ok.tar -C %USERPROFILE%\fcwork\out & dir"`,
		`cmd /c "tar -tf ok.tar && tar -xf ok.tar -C %USERPROFILE%"`,
		`cmd /x /c "dir & tar -xf ok.tar -C out"`,
		`cmd /c "echo homestate.tar & dir"`,
	}
	routes := []struct{ connector, tool string }{
		{"claudecode", "PowerShell"},
		{"codex", "Bash"},
	}
	tiers := []struct {
		name, posture, want string
		managed             bool
	}{
		{"default", "default", "alert", false},
		{"permissive", "permissive", "alert", false},
		{"strict", "strict", "block", false},
		{"managed", "default", "alert", true},
		{"managed-strict", "strict", "block", true},
	}
	for _, tier := range tiers {
		for _, route := range routes {
			installToolCallCorpusProfileConnector(t, route.connector, tier.posture)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = route.connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier.posture)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			ctx := context.Background()
			if tier.managed {
				ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
			}
			hook := hookRuntimeForProfile(api.hookProfileForRequest(ctx, route.connector))
			calls := 0
			evaluate := func(command string) (string, string) {
				calls++
				id := tier.name + "-" + route.connector + "-" + strconv.Itoa(calls)
				raw, err := json.Marshal(map[string]any{
					"session_id": "gap1667-" + id, "turn_id": "turn-1", "hook_event_name": "PreToolUse", "cwd": cwd,
					"model": "fixture-model", "tool_name": route.tool, "tool_use_id": "call-" + id,
					"tool_input": map[string]any{"command": command},
				})
				if err != nil {
					t.Fatal(err)
				}
				var payload map[string]interface{}
				if err := json.Unmarshal(raw, &payload); err != nil {
					t.Fatal(err)
				}
				args, err := json.Marshal(map[string]string{"command": command})
				if err != nil {
					t.Fatal(err)
				}
				resp, panicked := api.safeEvaluateHook(ctx, route.connector, agentHookRequest{ConnectorName: route.connector, CWD: cwd, HookEventName: "PreToolUse", ToolName: route.tool, ToolArgs: args}, raw, payload, hook)
				if panicked {
					t.Fatalf("%s %s/%s %q: hook evaluator panicked", tier.name, route.connector, route.tool, command)
				}
				return resp.Action, strings.Join(resp.Findings, "; ")
			}
			for _, command := range writes {
				action, findings := evaluate(command)
				want := tier.want
				if staged[command] && action == "block" && strings.Contains(findings, "persistence.ssh_authorized_keys_command") {
					want = "block"
				}
				if action != want || !strings.Contains(findings, "tamper.detector_state_write") {
					t.Errorf("%s %s/%s %q: %s [%s], want %s with tamper.detector_state_write", tier.name, route.connector, route.tool, command, action, findings, want)
				}
			}
			for _, command := range allowed {
				if action, findings := evaluate(command); action != "allow" {
					t.Errorf("%s %s/%s %q: %s [%s], want allow", tier.name, route.connector, route.tool, command, action, findings)
				}
			}
		}
	}
}
