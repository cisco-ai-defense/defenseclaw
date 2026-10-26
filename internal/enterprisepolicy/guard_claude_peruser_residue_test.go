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

// GAP-0587, GAP-1540: on a managed Windows computer, DefenseClaw's own older
// per-user Claude Code hooks in the account's ~/.claude/settings.json are
// DefenseClaw's, not foreign: a Copilot CLI session in a project under the
// home (whose project walk reaches that file) is not blocked on them while
// the guardian has not yet migrated them out. A foreign hook of the same
// shape is still blocked.
func TestGuardReadsDefenseClawPerUserClaudeHooksAsOwnNotForeign(t *testing.T) {
	t.Setenv("SystemRoot", `C:\Windows`)
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
	t.Run("product-written entries", func(t *testing.T) {
		req := newReq(t)
		var all []map[string]any
		for name, handler := range residueClaudeHandlers(req.Home) {
			writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"), claudeSettingsWith(t, handler))
			if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
				t.Fatalf("%s: DefenseClaw's own per-user Claude hook read as foreign: %+v", name, decision)
			}
			all = append(all, handler)
		}
		writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"), claudeSettingsWith(t, all...))
		if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
			t.Fatalf("all four forms in one matcher read as foreign: %+v", decision)
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
		"http hook": func(home string) map[string]any {
			h := residueClaudeHandlers(home)["exec"]
			h["type"] = "http"
			return h
		},
	}
	for name, build := range foreign {
		t.Run("foreign "+name, func(t *testing.T) {
			req := newReq(t)
			writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"), claudeSettingsWith(t, build(req.Home)))
			if decision := EvaluateForeignHooks(req); !decision.Deny || len(decision.Findings) != 1 {
				t.Fatalf("a foreign hook must still block: %+v", decision)
			}
		})
	}

	t.Run("product shape in another file", func(t *testing.T) {
		req := newReq(t)
		project := filepath.Join(req.WorkingDir, ".claude", "settings.json")
		writeFile(t, project, claudeSettingsWith(t, residueClaudeHandlers(req.Home)["exec"]))
		if decision := EvaluateForeignHooks(req); !decision.Deny || len(decision.Findings) != 1 {
			t.Fatalf("the per-user entry outside the account's Claude settings must stay foreign: %+v", decision)
		}
	})

	t.Run("without the account home", func(t *testing.T) {
		req := newReq(t)
		req.AccountHome = ""
		writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"), claudeSettingsWith(t, residueClaudeHandlers(req.Home)["exec"]))
		if decision := EvaluateForeignHooks(req); !decision.Deny {
			t.Fatalf("an entry the account database cannot place stays foreign: %+v", decision)
		}
	})

	t.Run("not on Windows", func(t *testing.T) {
		req := newReq(t)
		req.GOOS = "linux"
		req.Policy.Route = RouteFor(ConnectorCopilot, "linux")
		writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"), claudeSettingsWith(t, residueClaudeHandlers(req.Home)["exec"]))
		if decision := EvaluateForeignHooks(req); !decision.Deny {
			t.Fatalf("the Windows per-user forms are not DefenseClaw's elsewhere: %+v", decision)
		}
	})
}
