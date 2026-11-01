// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// residueClaudeHandlers are the per-user Claude Code handlers DefenseClaw's
// 1.0.x one-line Setup wrote on Windows for the launcher under home: the exec
// form (1.0.0, image-heritage profiles), the cmd.exe launcher guard (1.0.1 to
// 1.0.3) and the PreToolUse gateway guard (1.0.4).
func residueClaudeHandlers(home string) map[string]map[string]any {
	launcher := home + `\.local\bin\defenseclaw-hook.exe`
	cmdArgs := []any{"/d", "/c", "if", "exist", launcher, "(", launcher, "hook", "--connector", "claudecode", ")", "else", "(", "echo"}
	for _, word := range strings.Fields("DefenseClaw blocked this: its Claude Code hook launcher is missing. Run the DefenseClaw installer again to repair it.") {
		cmdArgs = append(cmdArgs, word)
	}
	cmdArgs = append(cmdArgs, "1>&2", "&", "exit", "/b", "2", ")")
	return map[string]map[string]any{
		"exec":       {"type": "command", "command": launcher, "args": []any{"hook", "--connector", "claudecode"}, "timeout": 30},
		"exec async": {"type": "command", "command": launcher, "args": []any{"hook", "--connector", "claudecode"}, "timeout": 30, "async": true},
		"cmd guard":  {"type": "command", "command": `C:\Windows\System32\cmd.exe`, "args": cmdArgs, "timeout": 30},
		"gateway guard": {"type": "command", "command": home + `\.local\bin\defenseclaw-gateway.exe`,
			"args": []any{"launcher-guard", launcher, "hook", "--connector", "claudecode"}, "timeout": 30},
	}
}

func claudeSettingsWith(t *testing.T, handlers ...map[string]any) string {
	t.Helper()
	list := make([]any, len(handlers))
	for i, handler := range handlers {
		list[i] = handler
	}
	data, err := json.Marshal(map[string]any{"hooks": map[string]any{
		"PreToolUse": []any{map[string]any{"matcher": "*", "hooks": list}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// GAP-1540, GAP-1852 (LEAD DECISION 03:34): ownership is proven by
// identity, never by shape. An entry with the exact shape of DefenseClaw's
// older per-user Claude Code hook in the account's ~/.claude/settings.json
// runs a launcher in the user's own home, which the user and any agent can
// write, so it is a foreign hook like any other: it blocks, and its finding
// and denial are the plain foreign ones (an attacker can plant that shape, so
// it must not get a benign-sounding label). Managed Setup and the guardian
// migrate the real old entries out before the guard enforces.
func TestGuardReadsDefenseClawPerUserClaudeHookShapeAsForeign(t *testing.T) {
	// A poisoned SystemRoot must not change how the cmd.exe guard reads.
	t.Setenv("SystemRoot", `D:\agent-root`)
	newReq := func(t *testing.T) GuardRequest {
		req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
		req.GOOS = "windows"
		req.Policy.Route = RouteFor(ConnectorCopilot, "windows")
		req.AccountHome = req.Home
		req.WorkingDir = filepath.Join(req.Home, "proj")
		if err := os.MkdirAll(req.WorkingDir, 0o700); err != nil {
			t.Fatal(err)
		}
		return req
	}
	settings := func(req GuardRequest) string { return filepath.Join(req.Home, ".claude", "settings.json") }
	assertForeign := func(t *testing.T, name string, decision GuardDecision) {
		t.Helper()
		if !decision.Deny || len(decision.Findings) != 1 {
			t.Fatalf("%s: must block as a foreign hook: %+v", name, decision)
		}
		if got := decision.Findings[0].Reason; got != "" {
			t.Fatalf("%s: finding reason = %q, want the plain foreign finding", name, got)
		}
		if !strings.HasPrefix(decision.Reason, "enterprise_foreign_hook_blocked: ") ||
			!strings.Contains(decision.Reason, " defines a hook (digest sha256:") ||
			!strings.Contains(decision.Reason, "Remove it, or ask your administrator to add the digest") ||
			strings.Contains(decision.Reason, "older DefenseClaw") {
			t.Fatalf("%s: denial is not the plain foreign-hook denial: %s", name, decision.Reason)
		}
	}

	forms := map[string]func(home string) map[string]any{}
	for name := range residueClaudeHandlers(`C:\x`) {
		forms["product shape "+name] = func(home string) map[string]any { return residueClaudeHandlers(home)[name] }
	}
	for name, build := range map[string]func(home string) map[string]any{
		"another launcher": func(home string) map[string]any {
			return map[string]any{"type": "command", "command": home + `\tools\defenseclaw-hook.exe`, "args": []any{"hook", "--connector", "claudecode"}}
		},
		"edited argv": func(home string) map[string]any {
			return map[string]any{"type": "command", "command": home + `\.local\bin\defenseclaw-hook.exe`, "args": []any{"hook", "--connector", "claudecode", "--api-addr", "10.0.0.1:1"}}
		},
		"extra env key": func(home string) map[string]any {
			h := residueClaudeHandlers(home)["exec"]
			h["env"] = map[string]any{"PATH": `C:\evil`}
			return h
		},
		"cmd guard run by the cmd.exe SystemRoot names": func(home string) map[string]any {
			h := residueClaudeHandlers(home)["cmd guard"]
			h["command"] = `D:\agent-root\System32\cmd.exe`
			return h
		},
	} {
		forms["foreign "+name] = build
	}
	for name, build := range forms {
		t.Run(name, func(t *testing.T) {
			req := newReq(t)
			writeFile(t, settings(req), claudeSettingsWith(t, build(req.Home)))
			assertForeign(t, name, EvaluateForeignHooks(req))
		})
	}
}
