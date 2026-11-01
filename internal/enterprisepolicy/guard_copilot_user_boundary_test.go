// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestCopilotIgnoresClaudeUserHooksOutsideTheHome(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
			req.GOOS = goos
			req.WorkingDir = t.TempDir()
			settings := filepath.Join(req.Home, ".claude", "settings.json")
			original := `{"hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"prettier --write"}]}]}}`
			writeFile(t, settings, original)
			if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
				t.Fatalf("Copilot CLI loads no Claude Code user hooks: %+v", decision)
			}
			result, err := CleanUserForeignHooks(req, time.Now())
			if err != nil || len(result.Removed) != 0 || result.BackupDir != "" {
				t.Fatalf("Copilot cleanup changed Claude Code settings: %+v, %v", result, err)
			}
			if data, err := os.ReadFile(settings); err != nil || string(data) != original {
				t.Fatalf("Claude Code settings changed: %q, %v", data, err)
			}
		})
	}
}

func TestCopilotVSCodeClaudeUserSourceStaysReportOnly(t *testing.T) {
	req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
	req.WorkingDir = t.TempDir()
	req.HookSurface = connector.CopilotHookSurfaceVSCodeLocal
	settings := filepath.Join(req.Home, ".claude", "settings.json")
	for _, source := range guardSources(req) {
		if samePath(source.path, settings) {
			if source.scope != ScopeUser || !source.reportOnly {
				t.Fatalf("VS Code Local Claude settings source = %+v", source)
			}
			return
		}
	}
	t.Fatal("VS Code Local Claude settings source missing")
}

func TestCopilotIgnoresDefenseClawClaudeUserRegistration(t *testing.T) {
	req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
	req.WorkingDir = t.TempDir()
	command := connector.PerUserOwnedHookCommands("claudecode", filepath.Join(req.Home, ".defenseclaw"))[0]
	req.OwnedCommands = connector.PerUserOwnedHookCommands("copilot", filepath.Join(req.Home, ".defenseclaw"))
	writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"),
		`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"`+strings.ReplaceAll(command, `"`, `\"`)+`"}]}]}}`)
	for _, route := range []string{RouteMachinePolicy, RoutePerUser} {
		req.Policy.Route = route
		if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
			t.Fatalf("Copilot route %s treated Claude Code registration as foreign: %+v", route, decision)
		}
	}
}

func TestCopilotProjectWalkCanReachClaudeSettingsInHome(t *testing.T) {
	req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
	req.WorkingDir = filepath.Join(req.Home, "work without git", "project")
	if err := os.MkdirAll(req.WorkingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"), foreignClaudeSettings)
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("home reached by project walk must be a project source: %+v", decision)
	}
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 0 || result.BackupDir != "" {
		t.Fatalf("project source was rewritten: %+v, %v", result, err)
	}
}

// A retained personal Claude registration can also be reached by Copilot's
// project walk. Retire the exact product command during managed cleanup;
// the guard must keep refusing it until that write succeeds.
func TestCopilotCleanupRetiresLegacyClaudeUserHook(t *testing.T) {
	req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
	req.GOOS = "windows"
	req.WorkingDir = filepath.Join(req.Home, "project")
	if err := os.MkdirAll(req.WorkingDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(req.Home, ".claude", "settings.json")
	legacy := `"` + filepath.Join(req.Home, ".local", "bin", "defenseclaw-hook.exe") + `" hook --connector claudecode`
	encode := func(command string) string {
		data, err := json.Marshal(map[string]any{"theme": "dark", "hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": command}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	writeFile(t, path, encode(legacy))
	if got := EvaluateForeignHooks(req); !got.Deny {
		t.Fatal("retained user binary was trusted before retirement")
	}
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 0 {
		t.Fatalf("unproven replacement changed the user hook: %+v, %v", result, err)
	}
	if got := EvaluateForeignHooks(req); !got.Deny {
		t.Fatal("unproven replacement opened the call")
	}
	req.RetireLegacyClaudeUserHooks = true
	result, err = CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 1 {
		t.Fatalf("cleanup=%+v, %v", result, err)
	}
	if got := EvaluateForeignHooks(req); got.Deny {
		t.Fatalf("retired legacy command still blocks: %+v", got)
	}
	data, err := os.ReadFile(path)
	var document map[string]any
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &document); err != nil || document["theme"] != "dark" {
		t.Fatalf("vendor setting lost: %v", err)
	}
	for _, command := range []string{"prettier --write", legacy + " --other"} {
		original := encode(command)
		writeFile(t, path, original)
		result, err := CleanUserForeignHooks(req, time.Now())
		if err != nil || len(result.Removed) != 0 {
			t.Fatalf("unproven registration changed: %+v, %v", result, err)
		}
		if after, err := os.ReadFile(path); err != nil || string(after) != original {
			t.Fatalf("foreign hook changed: %v", err)
		}
		if got := EvaluateForeignHooks(req); !got.Deny {
			t.Fatal("unproven hook became allowed")
		}
	}
	// Earlier installs used the gateway itself as the native hook runner.
	writeFile(t, path, encode(strings.Replace(legacy, "defenseclaw-hook.exe", "defenseclaw-gateway.exe", 1)))
	result, err = CleanUserForeignHooks(req, time.Now().Add(time.Minute))
	if err != nil || len(result.Removed) != 1 {
		t.Fatalf("legacy gateway registration was not retired: %+v, %v", result, err)
	}
	if got := EvaluateForeignHooks(req); got.Deny {
		t.Fatalf("retired legacy gateway still blocks: %+v", got)
	}
}

// The report shortens a finding's command; retirement must match the full
// command, or a long home leaves the retained registration blocking.
func TestCopilotCleanupRetiresLegacyClaudeUserHookUnderALongHome(t *testing.T) {
	req := guardRequest(t, ConnectorCopilot, config.ForeignHooksRemove)
	req.Home = filepath.Join(req.Home, strings.Repeat("h", 120))
	req.GOOS = "windows"
	req.WorkingDir = filepath.Join(req.Home, "project")
	if err := os.MkdirAll(req.WorkingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := `"` + filepath.Join(req.Home, ".local", "bin", "defenseclaw-hook.exe") + `" hook --connector claudecode`
	data, err := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": legacy}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(req.Home, ".claude", "settings.json"), string(data))
	req.RetireLegacyClaudeUserHooks = true
	if result, err := CleanUserForeignHooks(req, time.Now()); err != nil || len(result.Removed) != 1 {
		t.Fatalf("cleanup under a long home = %+v, %v", result, err)
	}
	if got := EvaluateForeignHooks(req); got.Deny {
		t.Fatalf("retired legacy command still blocks: %+v", got)
	}
}
