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

// GAP-0587, GAP-1540, review R1-1: an entry with the exact shape of
// DefenseClaw's older per-user Claude Code hook in the account's
// ~/.claude/settings.json is never read as DefenseClaw's own on a
// machine-policy connector. Its launcher sits in the user's home, which the
// user and any agent can write, so an agent that writes its own program
// there and adds the entry after Setup migrated the account must still be
// blocked. The guard only names such an entry as an older DefenseClaw hook
// (its own reason and advice); managed Setup and the guardian remove it.
func TestGuardBlocksDefenseClawPerUserClaudeHookShapeAndNamesIt(t *testing.T) {
	// A poisoned SystemRoot must neither name the cmd.exe guard's identity
	// nor change it: cmd.exe is the one the system directory API reports.
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

	t.Run("exact product shape re-added after the migration still blocks", func(t *testing.T) {
		req := newReq(t)
		for name, handler := range residueClaudeHandlers(req.Home) {
			writeFile(t, settings(req), claudeSettingsWith(t, handler))
			decision := EvaluateForeignHooks(req)
			if !decision.Deny || len(decision.Findings) != 1 {
				t.Fatalf("%s: a user-writable launcher was trusted as DefenseClaw's own hook: %+v", name, decision)
			}
			if got := decision.Findings[0].Reason; got != perUserClaudeReason {
				t.Fatalf("%s: finding reason = %q, want %q", name, got, perUserClaudeReason)
			}
			if !strings.HasPrefix(decision.Reason, "enterprise_foreign_hook_blocked: ") ||
				!strings.Contains(decision.Reason, "still holds an older DefenseClaw per-user Claude Code hook") ||
				!strings.Contains(decision.Reason, "managed Setup removes it") {
				t.Fatalf("%s: denial does not name the older DefenseClaw hook: %s", name, decision.Reason)
			}
		}
	})

	foreign := map[string]func(home string) map[string]any{
		"another launcher": func(home string) map[string]any {
			return map[string]any{"type": "command", "command": home + `\tools\defenseclaw-hook.exe`, "args": []any{"hook", "--connector", "claudecode"}}
		},
		"edited argv": func(home string) map[string]any {
			return map[string]any{"type": "command", "command": home + `\.local\bin\defenseclaw-hook.exe`, "args": []any{"hook", "--connector", "claudecode", "--api-addr", "10.0.0.1:1"}}
		},
		"command string with a tail": func(home string) map[string]any {
			return map[string]any{"type": "command", "command": `"` + home + `\.local\bin\defenseclaw-hook.exe" hook --connector claudecode & calc.exe`}
		},
		"extra env key": func(home string) map[string]any {
			h := residueClaudeHandlers(home)["exec"]
			h["env"] = map[string]any{"PATH": `C:\evil`}
			return h
		},
		"guard of another program": func(home string) map[string]any {
			h := residueClaudeHandlers(home)["gateway guard"]
			h["command"] = home + `\Downloads\defenseclaw-gateway.exe`
			return h
		},
		"cmd guard run by the cmd.exe SystemRoot names": func(home string) map[string]any {
			h := residueClaudeHandlers(home)["cmd guard"]
			h["command"] = `D:\agent-root\System32\cmd.exe`
			return h
		},
		"http hook": func(home string) map[string]any {
			h := residueClaudeHandlers(home)["exec"]
			h["type"] = "http"
			return h
		},
	}
	for name, build := range foreign {
		t.Run("foreign "+name, func(t *testing.T) {
			req := newReq(t)
			writeFile(t, settings(req), claudeSettingsWith(t, build(req.Home)))
			decision := EvaluateForeignHooks(req)
			if !decision.Deny || len(decision.Findings) != 1 {
				t.Fatalf("a foreign hook must still block: %+v", decision)
			}
			if decision.Findings[0].Reason == perUserClaudeReason {
				t.Fatalf("a foreign hook was named an older DefenseClaw hook: %+v", decision.Findings[0])
			}
		})
	}

	t.Run("product shape in another file is not named", func(t *testing.T) {
		req := newReq(t)
		writeFile(t, filepath.Join(req.WorkingDir, ".claude", "settings.json"), claudeSettingsWith(t, residueClaudeHandlers(req.Home)["exec"]))
		decision := EvaluateForeignHooks(req)
		if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Reason == perUserClaudeReason {
			t.Fatalf("the per-user shape outside the account's Claude settings: %+v", decision)
		}
	})

	t.Run("not on Windows", func(t *testing.T) {
		req := newReq(t)
		req.GOOS = "linux"
		req.Policy.Route = RouteFor(ConnectorCopilot, "linux")
		writeFile(t, settings(req), claudeSettingsWith(t, residueClaudeHandlers(req.Home)["exec"]))
		decision := EvaluateForeignHooks(req)
		if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Reason == perUserClaudeReason {
			t.Fatalf("the Windows per-user forms elsewhere: %+v", decision)
		}
	})
}
